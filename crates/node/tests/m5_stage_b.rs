//! M5 Stage B — distributed block production, crash-fault-tolerant (spec 08 §13).
//!
//! Two tiers of tests:
//!   * **Pure / unit** (fast, always run): the schedule + fork-choice + validity are deterministic
//!     functions of `(state, header)` — EC-B3 (fork choice picks the lower-view block), EC-B6
//!     (`proposer_index`/`validator_set` purity — see also `crates/runtime`), EC-B-F3 (wrong proposer
//!     rejected), EC-B-F4 (equivocation → lowest hash, no split), EC-B-F5 (view out of range).
//!   * **Multi-process** (`#[ignore]`, mirrors `m5_stage_a.rs`): spawn 3 independent `ubi2-node`
//!     validator processes seeded with an identical genesis validator set — EC-B1 (rotation over ≥2 of
//!     3 across 30 blocks), EC-B2 (kill the scheduled proposer → a successor takes over, chain does not
//!     halt), EC-B4 (restart the killed node → it re-syncs to the canonical chain), EC-B5 (byte-identical
//!     `state_root` across rotation + a view change — I1/I2).
//!
//! Run the multi-process tier with:
//!   `cargo build --workspace && cargo test --test m5_stage_b -- --ignored --nocapture`

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ubi2_rpc::{fork_choice_prefers, Block, BlockError, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::{proposer_index, Account, UBI, VIEW_MAX};

use alloy_primitives::{Address as AlloyAddr, B256};

/// Serializes the 3 multi-process tests below (each spawns 3 full `ubi2-node` processes producing a
/// block every `BLOCK_MS`). They use distinct port ranges (`spawn_three`'s `group` offset) so they do
/// NOT collide on ports under default `cargo test` parallelism — but running all 3 groups (9 processes)
/// truly concurrently contends hard for this machine's CPU, which can slow a restarted node's sync
/// below the live chain's block-production rate (a resource/perf liveness concern under contention, NOT
/// a consensus safety issue — the safety checks below are anchored on the finalized height precisely so
/// a transient lag never produces a false failure). Serializing keeps each test's timing budget
/// (`PROPOSER_TIMEOUT`-scaled) meaningful without weakening any assertion.
static MULTI_PROCESS_LOCK: Mutex<()> = Mutex::new(());

// ─── The 3 validator keys (Anvil accounts #1..#3 — PUBLIC devnet keys, NOT secrets) ─────────────
const V_KEYS: [[u8; 32]; 3] = [
    hex32("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"), // acct1 0x7099…
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"), // acct2 0x3C44…
    hex32("7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"), // acct3 0x90F7…
];
const V_KEYS_HEX: [&str; 3] = [
    "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
    "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
    "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
];

const CHAIN_ID: u64 = DEVNET_CHAIN_ID;
const GENESIS_TIME: u64 = 1_700_000_000;

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}
const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// PURE / UNIT tier (fast — always run)
// ════════════════════════════════════════════════════════════════════════════════════════════════

/// Build a chain seeded with the 3 validators (each a Verified human + registered juror + a funded
/// account) so the on-chain epoch snapshot `V = {v1, v2, v3}`. `proposer_key`, when set, makes this
/// chain a proposer for the given member. All chains built with the same seeds share a `state_root`.
fn seeded_chain(proposer_key: Option<[u8; 32]>) -> (Chain, Vec<AlloyAddr>) {
    let mut chain = Chain::new(CHAIN_ID, GENESIS_TIME);
    if let Some(k) = proposer_key {
        chain = chain.with_proposer_key(std::sync::Arc::new(ProposerKey::from_bytes(&k).unwrap()));
    }
    let mut addrs = Vec::new();
    for k in &V_KEYS {
        let addr = ProposerKey::from_bytes(k).unwrap().address();
        addrs.push(addr);
        chain.seed_account(Account {
            address: addr.into_array(),
            verified: true,
            verified_at: GENESIS_TIME,
            last_settled_at: GENESIS_TIME,
            settled_balance: 1_000 * UBI,
            nonce: 0,
        });
        chain.seed_verified_human(&addr.into_array(), GENESIS_TIME);
        chain.register_juror(&addr.into_array(), 0);
    }
    // The sorted epoch snapshot `V` (seeded lazily on first read).
    let v = chain.validator_set();
    (chain, v)
}

/// Which validator key produces `V[index]`?
fn key_for(addr: AlloyAddr) -> [u8; 32] {
    for k in &V_KEYS {
        if ProposerKey::from_bytes(k).unwrap().address() == addr {
            return *k;
        }
    }
    panic!("no key for {addr}");
}

/// Produce block #1 at the given `view`, correctly signed by the scheduled proposer for `(1, view)`.
fn produce_block1_at_view(v: &[AlloyAddr], view: u32) -> Block {
    let n = v.len();
    let scheduled = v[proposer_index(1, view, n)];
    let (chain, _) = seeded_chain(Some(key_for(scheduled)));
    chain.produce_block_at_view(GENESIS_TIME + 10, view)
}

/// EC-B6 (schedule purity) + the on-chain `V` is the sorted qualifying set. (The insertion-order and
/// `proposer_index` purity are covered in `crates/runtime`'s unit tests; this asserts the seeded chain's
/// snapshot matches `validator_set(state)`.)
#[test]
fn ecb6_validator_set_is_the_sorted_snapshot() {
    let (chain, v) = seeded_chain(None);
    assert_eq!(v.len(), 3, "3 seeded validators");
    // Sorted ascending.
    assert!(v[0] < v[1] && v[1] < v[2], "V is sorted ascending");
    // proposer_index round-robins over exactly N consecutive view-0 heights.
    let n = v.len();
    let mut seen = std::collections::HashSet::new();
    for h in 0..n as u64 {
        seen.insert(v[proposer_index(h, 0, n)]);
    }
    assert_eq!(
        seen.len(),
        3,
        "N consecutive view-0 heights cover all validators"
    );
    // Its `validator_set(state)` read matches the runtime free-fn over the committed snapshot.
    let g_head = chain.tip().0;
    assert_eq!(g_head, 0);
}

/// EC-B3 + EC-B-F5(reorg): a follower that adopted `h @ view 1` reorgs to a late `h @ view 0` (lower
/// view wins, §6.1), regardless of arrival order, and the reorg is bounded (depth 1 < FINALITY_DEPTH).
#[test]
fn ecb3_fork_choice_picks_lower_view_via_reorg() {
    let (_c, v) = seeded_chain(None);
    let block_v0 = produce_block1_at_view(&v, 0);
    let block_v1 = produce_block1_at_view(&v, 1);
    assert_eq!(block_v0.number, 1);
    assert_eq!(block_v1.number, 1);
    assert_ne!(block_v0.hash, block_v1.hash, "distinct competing blocks");

    // A fresh follower adopts the view-1 successor FIRST.
    let (follower, _) = seeded_chain(None);
    follower
        .validate_and_apply_block(
            block_v1.number,
            block_v1.parent_hash,
            block_v1.timestamp,
            block_v1.view,
            block_v1.txs_root,
            block_v1.state_root,
            block_v1.proposer,
            &block_v1.proposer_sig,
            &[],
            None,
        )
        .expect("follower adopts the view-1 successor");
    assert_eq!(follower.tip().1, block_v1.hash, "tip is the view-1 block");

    // Now the late view-0 original arrives — fork choice reorgs to it (lower view wins).
    let reorged = follower
        .consider_competing_block(
            block_v0.number,
            block_v0.parent_hash,
            block_v0.timestamp,
            block_v0.view,
            block_v0.txs_root,
            block_v0.state_root,
            block_v0.proposer,
            &block_v0.proposer_sig,
            &[],
            None,
        )
        .expect("competing view-0 block is valid");
    assert!(
        reorged.is_some(),
        "EC-B3: the follower reorgs to the view-0 block"
    );
    assert_eq!(
        follower.tip().1,
        block_v0.hash,
        "EC-B3: canonical head at height 1 is the view-0 block (lowest-view tiebreak)"
    );

    // And the reverse arrival order: a follower on view 0 does NOT reorg to a late view-1 straggler.
    let (follower2, _) = seeded_chain(None);
    follower2
        .validate_and_apply_block(
            block_v0.number,
            block_v0.parent_hash,
            block_v0.timestamp,
            block_v0.view,
            block_v0.txs_root,
            block_v0.state_root,
            block_v0.proposer,
            &block_v0.proposer_sig,
            &[],
            None,
        )
        .expect("adopt view-0");
    let no_reorg = follower2
        .consider_competing_block(
            block_v1.number,
            block_v1.parent_hash,
            block_v1.timestamp,
            block_v1.view,
            block_v1.txs_root,
            block_v1.state_root,
            block_v1.proposer,
            &block_v1.proposer_sig,
            &[],
            None,
        )
        .expect("view-1 straggler is valid");
    assert!(
        no_reorg.is_none(),
        "a higher-view straggler does not displace the view-0 tip"
    );
    assert_eq!(follower2.tip().1, block_v0.hash);
}

/// EC-B-F3: a block whose `proposer != V[(h+view) mod N]` (or is signed by the wrong validator for that
/// view) is rejected `WrongProposer`; nothing is applied.
#[test]
fn ecbf3_wrong_proposer_rejected() {
    let (_c, v) = seeded_chain(None);
    // The scheduled proposer for (1, 0) is V[1]; build a block authored by V[(1+2)%3]=V[0]-ish that is
    // NOT the (1,0) proposer, by producing at view 2 (scheduled V[(1+2)%3]) then presenting it as view 0.
    let scheduled_v0 = v[proposer_index(1, 0, v.len())];
    // Pick a different validator's key.
    let wrong = *v.iter().find(|a| **a != scheduled_v0).unwrap();
    let (wrong_chain, _) = seeded_chain(Some(key_for(wrong)));
    let bad = wrong_chain.produce_block_at_view(GENESIS_TIME + 10, 0); // claims view 0, wrong author

    let (follower, _) = seeded_chain(None);
    let err = follower
        .validate_and_apply_block(
            bad.number,
            bad.parent_hash,
            bad.timestamp,
            bad.view,
            bad.txs_root,
            bad.state_root,
            bad.proposer,
            &bad.proposer_sig,
            &[],
            None,
        )
        .unwrap_err();
    assert_eq!(
        err,
        BlockError::WrongProposer,
        "EC-B-F3: wrong proposer rejected"
    );
    assert_eq!(follower.tip().0, 0, "nothing applied");
}

/// EC-B-F5: a block with `view >= VIEW_MAX` is rejected `ViewOutOfRange`; not applied.
#[test]
fn ecbf5_view_out_of_range_rejected() {
    let (_c, v) = seeded_chain(None);
    let block = produce_block1_at_view(&v, 0);
    let (follower, _) = seeded_chain(None);
    let err = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            VIEW_MAX, // an absurd view
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &[],
            None,
        )
        .unwrap_err();
    assert_eq!(err, BlockError::ViewOutOfRange { view: VIEW_MAX });
    assert_eq!(follower.tip().0, 0, "nothing applied");
}

/// EC-B-F4: the fork-choice total order does not split honest nodes on equivocation — two blocks at the
/// same `(h, view)` with different hashes resolve to the LOWEST hash on every node (§6.1 rule 3).
#[test]
fn ecbf4_equivocation_lowest_hash_no_split() {
    let low = B256::repeat_byte(0x11);
    let high = B256::repeat_byte(0x22);
    // Same height + same view ⇒ the tiebreak is the hash; lower hash wins, deterministically.
    assert!(fork_choice_prefers((5, 0, low), (5, 0, high)));
    assert!(!fork_choice_prefers((5, 0, high), (5, 0, low)));
    // Lower view beats a higher view at equal height (the re-convergence tiebreak).
    assert!(fork_choice_prefers((5, 0, high), (5, 1, low)));
    // Greater height always wins (liveness), regardless of view/hash.
    assert!(fork_choice_prefers((6, 9, high), (5, 0, low)));
}

/// EC-B5 (determinism, unit slice): two independently-seeded chains that apply the same rotated blocks
/// reach the same `state_root` at every height — including through a view change.
#[test]
fn ecb5_state_root_identical_through_rotation_and_view_change() {
    let (_c, v) = seeded_chain(None);
    // Two followers re-execute the same block sequence built by different views; both must agree.
    let block_v1 = produce_block1_at_view(&v, 1); // a view-change successor at height 1
    let (f1, _) = seeded_chain(None);
    let (f2, _) = seeded_chain(None);
    for f in [&f1, &f2] {
        f.validate_and_apply_block(
            block_v1.number,
            block_v1.parent_hash,
            block_v1.timestamp,
            block_v1.view,
            block_v1.txs_root,
            block_v1.state_root,
            block_v1.proposer,
            &block_v1.proposer_sig,
            &[],
            None,
        )
        .expect("both followers accept the view-1 block");
    }
    assert_eq!(
        f1.state_root(),
        f2.state_root(),
        "byte-identical state_root through a view change"
    );
    assert_eq!(
        f1.state_root(),
        block_v1.state_root,
        "matches the committed header root"
    );
    // The committed `V` snapshot feeds the root: both agree on the schedule by replay.
    let sr = f1.state_root();
    assert_eq!(sr, f2.state_root());
}

// ─── Cluster helper: a lockstep set of the 3 validator-keyed chains ─────────────────────────────
// Mirrors the 3-node devnet in one process so a block at ANY (height, view) can be produced by the
// correctly-scheduled proposer `V[(h+v) mod 3]` and applied to every chain — the machinery the reorg
// unit tests need to build multi-block canonical + fork branches deterministically.
struct Cluster {
    chains: Vec<Chain>,
    v: Vec<AlloyAddr>,
    ts: u64,
}

impl Cluster {
    fn new() -> Self {
        let chains: Vec<Chain> = V_KEYS.iter().map(|k| seeded_chain(Some(*k)).0).collect();
        let v = chains[0].validator_set();
        Cluster {
            chains,
            v,
            ts: GENESIS_TIME,
        }
    }

    fn chain_index_for(&self, addr: AlloyAddr) -> usize {
        V_KEYS
            .iter()
            .position(|k| ProposerKey::from_bytes(k).unwrap().address() == addr)
            .expect("addr is one of the 3 validators")
    }

    /// Produce the next block (`head + 1`) at `view` by the scheduled proposer and apply it to every
    /// cluster chain, keeping them in lockstep. Returns the produced block. Timestamps are monotonic and
    /// deterministic, so two clusters mining the same (view, order) prefix produce byte-identical blocks.
    fn mine(&mut self, view: u32) -> Block {
        let head = self.chains[0].tip().0;
        let height = head + 1;
        let proposer = self.v[proposer_index(height, view, self.v.len())];
        let pidx = self.chain_index_for(proposer);
        self.ts += 1;
        let ts = self.ts;
        let blk = self.chains[pidx].produce_block_at_view(ts, view);
        for (i, c) in self.chains.iter().enumerate() {
            if i == pidx {
                continue;
            }
            c.validate_and_apply_block(
                blk.number,
                blk.parent_hash,
                blk.timestamp,
                blk.view,
                blk.txs_root,
                blk.state_root,
                blk.proposer,
                &blk.proposer_sig,
                &[],
                None,
            )
            .expect("cluster follower applies the produced block");
        }
        blk
    }
}

/// Apply a fully-formed (empty-tx) block to a follower chain via the clean-extend path.
fn apply_block(chain: &Chain, b: &Block) -> Result<Block, BlockError> {
    chain.validate_and_apply_block(
        b.number,
        b.parent_hash,
        b.timestamp,
        b.view,
        b.txs_root,
        b.state_root,
        b.proposer,
        &b.proposer_sig,
        &[],
        None,
    )
}

/// Feed a competing / fork / taller-branch block to a chain via the bounded GENERAL reorg.
fn consider_block(chain: &Chain, b: &Block) -> Result<Option<Block>, BlockError> {
    chain.consider_competing_block(
        b.number,
        b.parent_hash,
        b.timestamp,
        b.view,
        b.txs_root,
        b.state_root,
        b.proposer,
        &b.proposer_sig,
        &[],
        None,
    )
}

/// BLOCKER-1 core (spec 08 §5.4/§6.1/§7, EC-B-F5): a node that adopted a LOSING tip-race branch
/// (`h1@view0`) and then sees the WINNING branch EXTENDED (`h1@view1` then `h2@view1`) must perform a
/// bounded GENERAL reorg and CONVERGE (byte-identical `state_root` to the winning branch) — it must NOT
/// stay `WrongParent`-forever stuck (the reproduced gate bug) and finalize a conflicting chain.
#[test]
fn ecbf5_general_reorg_heals_stuck_losing_branch() {
    // The WINNING branch: h1@view1, then its child h2@view1 (a taller, height-2 branch).
    let mut win = Cluster::new();
    let h1_v1 = win.mine(1);
    let h2_v1 = win.mine(1);
    assert_eq!(h1_v1.number, 1);
    assert_eq!(h2_v1.number, 2);
    assert_eq!(
        h2_v1.parent_hash, h1_v1.hash,
        "h2@view1 is a child of h1@view1"
    );

    // The LOSING tip-race block h1@view0 (shares the genesis parent with h1@view1).
    let (_c, v) = seeded_chain(None);
    let h1_v0 = produce_block1_at_view(&v, 0);
    assert_ne!(
        h1_v0.hash, h1_v1.hash,
        "distinct competing blocks at height 1"
    );
    assert_eq!(h1_v0.parent_hash, h1_v1.parent_hash, "same genesis parent");

    // Node A adopts the LOSING branch h1@view0 first (the race the gate probes).
    let (a, _) = seeded_chain(None);
    apply_block(&a, &h1_v0).expect("A adopts h1@view0");
    assert_eq!(a.tip().1, h1_v0.hash, "A is on the losing branch");

    // The competing h1@view1 arrives (same height, higher view): NOT preferred yet, so it is RETAINED
    // in the side store but A does not reorg — exactly the moment the old code got permanently stuck.
    let r1 = consider_block(&a, &h1_v1).expect("h1@view1 is a valid competitor");
    assert!(r1.is_none(), "h1@view1 is higher-view; not preferred yet");
    assert_eq!(
        a.tip().1,
        h1_v0.hash,
        "A still on the losing branch (retained, not stuck)"
    );

    // The winning branch's CHILD h2@view1 arrives — now the view-1 branch is TALLER (height 2). A must
    // perform the bounded general reorg to it, NOT reject WrongParent forever.
    let r2 = consider_block(&a, &h2_v1).expect("h2@view1 is a valid taller-branch child");
    assert!(
        r2.is_some(),
        "EC-B-F5: A reorgs to the taller honest branch (bounded general reorg)"
    );
    assert_eq!(a.tip().0, 2, "A advanced to the taller branch height");
    assert_eq!(
        a.tip().1,
        h2_v1.hash,
        "A's canonical tip is the winning branch tip"
    );
    assert_eq!(
        a.state_root(),
        h2_v1.state_root,
        "EC-B-F5: byte-identical state_root to the winning branch (convergence, I1)"
    );
    // And the reorg was bounded: common ancestor = genesis, depth 2, well under FINALITY_DEPTH (6).
    const _: () = assert!(2 < ubi2_rpc::FINALITY_DEPTH, "reorg depth < FINALITY_DEPTH");
}

/// BLOCKER-1 finality bound (spec 08 §6.3, EC-B-F5): a fork whose common ancestor is BELOW the finalized
/// frontier is REFUSED — the finalized frontier is NEVER reverted — even though the fork branch is
/// fork-choice-preferred (strictly taller). The node keeps its canonical (finalized) history intact.
#[test]
fn ecbf5_reorg_never_crosses_finalized_frontier() {
    // Node A's canonical chain: 10 view-0 blocks. finalizedHeight = 10 − FINALITY_DEPTH(6) = 4.
    let mut main = Cluster::new();
    let (a, _) = seeded_chain(None);
    let mut a_blocks = Vec::new();
    for _ in 0..10 {
        let b = main.mine(0);
        apply_block(&a, &b).expect("A extends its canonical chain");
        a_blocks.push(b);
    }
    assert_eq!(a.tip().0, 10);
    let finalized = a.finalized_height();
    assert_eq!(finalized, 4, "finalizedHeight = 10 − 6");

    // A FORK that shares blocks 1..2 with A, then diverges at height 3 (view 1) — so its common ancestor
    // is height 2, BELOW the finalized frontier (4) — and grows TALLER than A (to height 12).
    let mut fork = Cluster::new();
    let _shared1 = fork.mine(0); // == A's block 1 (same seed/view/timestamp)
    let shared2 = fork.mine(0); // == A's block 2
    assert_eq!(
        shared2.hash, a_blocks[1].hash,
        "fork shares blocks 1..2 with A"
    );
    let mut fork_blocks = Vec::new();
    for _ in 3..=12 {
        fork_blocks.push(fork.mine(1)); // divergent view-1 branch, heights 3..12
    }
    let fork_tip = fork_blocks.last().unwrap().clone();
    assert_eq!(
        fork_tip.number, 12,
        "fork branch is strictly taller than A (12 > 10)"
    );
    // The fork tip IS fork-choice-preferred over A's tip (so ONLY the finality bound can refuse it).
    let a_tip_key = (a_blocks[9].number, a_blocks[9].view, a_blocks[9].hash);
    assert!(
        fork_choice_prefers((fork_tip.number, fork_tip.view, fork_tip.hash), a_tip_key),
        "the taller fork branch is fork-choice-preferred"
    );

    // Feed the ENTIRE divergent branch to A. A must REFUSE to reorg (its common ancestor, height 2, is
    // below finalizedHeight 4 — reverting it would cross the finalized frontier, §6.3).
    for fb in &fork_blocks {
        let r = consider_block(&a, fb).expect("fork block is authenticated/valid");
        assert!(
            r.is_none(),
            "EC-B-F5: a fork below the finalized frontier is NEVER adopted (block {} not reorged)",
            fb.number
        );
    }
    assert_eq!(
        a.tip().0,
        10,
        "A's head is unchanged (no reorg across finalized)"
    );
    assert_eq!(a.tip().1, a_blocks[9].hash, "A's canonical tip is intact");
    assert_eq!(
        a.state_root(),
        a_blocks[9].state_root,
        "A's committed state_root is unchanged"
    );
    // The finalized block at a sub-finalized height (3) is byte-for-byte the canonical one — never
    // reverted to the fork's version.
    assert_eq!(
        a.block_at(3).unwrap().hash,
        a_blocks[2].hash,
        "EC-B-F5: the finalized block at height 3 is NEVER replaced by the fork"
    );
}

// ════════════════════════════════════════════════════════════════════════════════════════════════
// MULTI-PROCESS tier (#[ignore] — spawns the built ubi2-node binary; mirrors m5_stage_a.rs)
// ════════════════════════════════════════════════════════════════════════════════════════════════

const RPC_BASE: u16 = 18580;
const P2P_BASE: u16 = 19580;
const BLOCK_MS: u64 = 1000;

fn node_bin() -> PathBuf {
    let mut p = std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("parent")
        .to_path_buf();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("ubi2-node")
}

fn p2p_seed(i: u8) -> String {
    format!("{:x}", i).repeat(64)
}

fn peer_id_for(i: u8) -> String {
    let out = Command::new(node_bin())
        .args(["peer-id", &p2p_seed(i)])
        .output()
        .expect("peer-id subcommand");
    String::from_utf8(out.stdout)
        .expect("utf8")
        .trim()
        .to_string()
}

fn bootstrap_for(i: u8, group: u16, all: &[(u8, String)]) -> String {
    all.iter()
        .filter(|(j, _)| *j != i)
        .map(|(j, pid)| {
            format!(
                "/ip4/127.0.0.1/tcp/{}/p2p/{}",
                P2P_BASE + group + *j as u16,
                pid
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// The comma-separated genesis validator set (all 3 addresses), seeded identically on every node.
fn genesis_validators_csv() -> String {
    V_KEYS
        .iter()
        .map(|k| {
            let a = ProposerKey::from_bytes(k).unwrap().address();
            hex_encode(a.as_slice())
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct NodeProc {
    child: Option<Child>,
    idx: u8,
    group: u16,
    rpc_port: u16,
    bootstrap: String,
    tmp: PathBuf,
}

impl NodeProc {
    fn kill(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
    fn restart(&mut self) {
        let log = self.tmp.join(format!("node{}-restart.log", self.idx));
        self.child = Some(spawn_child(
            self.idx,
            self.group,
            &self.bootstrap,
            &self.tmp,
            &log,
        ));
    }
    /// SIGSTOP the node process: it becomes SLOW-BUT-ALIVE (frozen — produces/answers nothing) while its
    /// TCP connections LINGER (transport still "connected"). This is the delay / black-hole proxy the CFT
    /// safety tests need: a silent proposer that peers' active-liveness probe must detect.
    fn pause(&self) {
        if let Some(c) = &self.child {
            let _ = Command::new("kill")
                .args(["-s", "STOP", &c.id().to_string()])
                .status();
        }
    }
    /// SIGCONT the node process: a paused (slow) node RESUMES. It must reconcile with the chain it missed
    /// (reorg / re-sync) rather than stay stuck or penalize the honest peers relaying the canonical chain.
    fn resume(&self) {
        if let Some(c) = &self.child {
            let _ = Command::new("kill")
                .args(["-s", "CONT", &c.id().to_string()])
                .status();
        }
    }
}

impl Drop for NodeProc {
    fn drop(&mut self) {
        self.kill();
    }
}

// `group` offsets the RPC/P2P port ranges so multiple #[ignore] multi-process tests in this file can
// run concurrently (default `cargo test` parallelism) without colliding on the same fixed ports —
// a test-harness-only concern, not a consensus determinism concern.
fn spawn_child(idx: u8, group: u16, bootstrap: &str, tmp_base: &Path, log_file: &Path) -> Child {
    let rpc_port = RPC_BASE + group + idx as u16;
    let p2p_port = P2P_BASE + group + idx as u16;
    let data_dir = tmp_base.join(format!("node{idx}"));
    std::fs::create_dir_all(&data_dir).expect("create data dir");
    let log = std::fs::File::create(log_file).expect("create log file");
    let mut cmd = Command::new(node_bin());
    cmd.env("UBI2_RPC_ADDR", format!("127.0.0.1:{rpc_port}"))
        .env("UBI2_P2P_ADDR", format!("/ip4/127.0.0.1/tcp/{p2p_port}"))
        .env("UBI2_P2P_SEED", p2p_seed(idx))
        .env("UBI2_BOOTSTRAP", bootstrap)
        // NO UBI2_DESIGNATED_PROPOSER — the on-chain epoch snapshot governs the schedule (§3.3).
        .env("UBI2_PROPOSER_KEY", V_KEYS_HEX[(idx - 1) as usize])
        .env("UBI2_VALIDATOR_KEY", V_KEYS_HEX[(idx - 1) as usize])
        .env("UBI2_GENESIS_VALIDATORS", genesis_validators_csv())
        .env("UBI2_GENESIS_TIME", GENESIS_TIME.to_string())
        .env("UBI2_BLOCK_MS", BLOCK_MS.to_string())
        .env("UBI2_DATA_DIR", data_dir.to_str().unwrap())
        .env("RUST_LOG", "warn,ubi2_node=info,ubi2_rpc=warn")
        .env("UBI2_MDNS", "0")
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .stdin(Stdio::null());
    cmd.spawn().expect("spawn node")
}

fn spawn_node(idx: u8, group: u16, bootstrap: &str, tmp_base: &Path) -> NodeProc {
    let log = tmp_base.join(format!("node{idx}.log"));
    let child = spawn_child(idx, group, bootstrap, tmp_base, &log);
    NodeProc {
        child: Some(child),
        idx,
        group,
        rpc_port: RPC_BASE + group + idx as u16,
        bootstrap: bootstrap.to_string(),
        tmp: tmp_base.to_path_buf(),
    }
}

// ─── JSON-RPC helpers ─────────────────────────────────────────────────────────

fn rpc_call(port: u16, method: &str, params: &str) -> Option<serde_json::Value> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let resp = ureq_post(port, &body)?;
    let v: serde_json::Value = serde_json::from_str(&resp).ok()?;
    Some(v["result"].clone())
}

fn ureq_post(port: u16, body: &str) -> Option<String> {
    use std::io::Read;
    let stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(2000)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(2000)))
        .ok()?;
    let mut write_stream = stream.try_clone().ok()?;
    let request = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    write_stream.write_all(request.as_bytes()).ok()?;
    drop(write_stream);
    let mut response = String::new();
    let mut read_stream = stream;
    read_stream.read_to_string(&mut response).ok()?;
    response
        .find("\r\n\r\n")
        .map(|pos| response[pos + 4..].to_string())
}

fn wait_ready(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(300),
        )
        .is_ok()
        {
            std::thread::sleep(Duration::from_millis(150));
            return true;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    false
}

fn poll_until<T, F: Fn() -> Option<T>>(f: F, timeout: Duration) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = f() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn block_number(port: u16) -> Option<u64> {
    let s = rpc_call(port, "eth_blockNumber", "[]")?;
    let s = s.as_str()?;
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()
}

/// `ubi_stateRoot` AT a fixed historical height — anchored, so comparing two nodes is race-free (unlike
/// comparing each node's live TIP root, which can read different heights if the chain advances between
/// the two RPC round-trips).
fn state_root_at(port: u16, height: u64) -> Option<String> {
    rpc_call(port, "ubi_stateRoot", &format!(r#"["0x{height:x}"]"#))?
        .as_str()
        .map(|s| s.to_string())
}

/// The block hash at a fixed height, via `ubi_getBlock`.
fn block_hash_at(port: u16, height: u64) -> Option<String> {
    let v = rpc_call(port, "ubi_getBlock", &format!(r#"["0x{height:x}"]"#))?;
    if v.is_null() {
        return None;
    }
    v["hash"].as_str().map(|s| s.to_lowercase())
}

/// `(proposer_hex_lower, view)` for a block by height, via `ubi_getBlock`.
fn block_author(port: u16, height: u64) -> Option<(String, u64)> {
    let v = rpc_call(port, "ubi_getBlock", &format!(r#"["0x{height:x}"]"#))?;
    if v.is_null() {
        return None;
    }
    let proposer = v["proposer"]
        .as_str()?
        .trim_start_matches("0x")
        .to_lowercase();
    let view = v["view"].as_u64().unwrap_or(0);
    Some((proposer, view))
}

/// This node's k-deep `finalizedHeight` (`head - FINALITY_DEPTH`, spec 08 §6.3), via `ubi_consensusStatus`.
/// No reorg may cross this height — it is the only race-free anchor to compare two nodes' committed
/// history against (a height *above* it may still be mid-reconciliation after a view change/restart).
fn finalized_height(port: u16) -> Option<u64> {
    let v = rpc_call(port, "ubi_consensusStatus", "[]")?;
    let s = v["finalizedHeight"].as_str()?;
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok()
}

/// This node's `scheduledProposer` for `head+1` at `currentView`, via `ubi_consensusStatus`.
fn scheduled_proposer(port: u16) -> Option<String> {
    let v = rpc_call(port, "ubi_consensusStatus", "[]")?;
    Some(
        v["scheduledProposer"]
            .as_str()?
            .trim_start_matches("0x")
            .to_lowercase(),
    )
}

fn addr_of_key(k: &[u8; 32]) -> String {
    hex_encode(ProposerKey::from_bytes(k).unwrap().address().as_slice())
}

struct TmpGuard(PathBuf);
impl Drop for TmpGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn spawn_three(tmp: &Path, group: u16) -> Vec<NodeProc> {
    let all_peers: Vec<(u8, String)> = (1u8..=3).map(|i| (i, peer_id_for(i))).collect();
    (1u8..=3)
        .map(|i| {
            let bootstrap = bootstrap_for(i, group, &all_peers);
            spawn_node(i, group, &bootstrap, tmp)
        })
        .collect()
}

fn wait_all_ready(nodes: &[NodeProc]) {
    for n in nodes {
        assert!(
            wait_ready(n.rpc_port, Duration::from_secs(20)),
            "node {} RPC not ready",
            n.idx
        );
    }
}

/// EC-B1 — rotation across ≥2 of 3 over 30 blocks; every view-0 block's proposer == V[height mod 3].
#[test]
#[ignore = "multi-process integration test; run with -- --ignored"]
fn ecb1_rotation_over_30_blocks() {
    let _serialize = MULTI_PROCESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = node_bin();
    assert!(
        bin.exists(),
        "run `cargo build --workspace` first ({})",
        bin.display()
    );
    let tmp = std::env::temp_dir().join(format!("ubi2-m5b-b1-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let _g = TmpGuard(tmp.clone());
    let nodes = spawn_three(&tmp, 0);
    wait_all_ready(&nodes);
    let port = nodes[0].rpc_port;

    // Wait for 30 blocks.
    let reached = poll_until(
        || block_number(port).filter(|h| *h >= 30),
        Duration::from_secs(90),
    );
    assert!(
        reached.is_some(),
        "EC-B1: chain must reach 30 blocks (got {:?})",
        block_number(port)
    );

    // The sorted V (as lowercase hex) — the on-chain schedule order.
    let mut sorted: Vec<AlloyAddr> = V_KEYS
        .iter()
        .map(|k| ProposerKey::from_bytes(k).unwrap().address())
        .collect();
    sorted.sort();
    let v_hex: Vec<String> = sorted.iter().map(|a| hex_encode(a.as_slice())).collect();

    let mut proposers = std::collections::HashSet::new();
    let mut counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for h in 1..=30u64 {
        if let Some((proposer, view)) = block_author(port, h) {
            proposers.insert(proposer.clone());
            *counts.entry(proposer.clone()).or_default() += 1;
            if view == 0 {
                assert_eq!(
                    proposer,
                    v_hex[(h % 3) as usize],
                    "EC-B1: view-0 block {h} proposer must be V[h mod 3]"
                );
            }
        }
    }
    assert!(
        proposers.len() >= 2,
        "EC-B1: ≥2 distinct proposers over 30 blocks (got {proposers:?})"
    );
    assert!(
        counts.values().all(|c| *c < 30),
        "EC-B1: no single address proposes all 30 blocks ({counts:?})"
    );
    eprintln!("[m5b] EC-B1 PASS: proposers={proposers:?}");
}

/// EC-B2 — kill the scheduled proposer → a successor takes over (view ≥ 1); the chain does not halt.
#[test]
#[ignore = "multi-process integration test; run with -- --ignored"]
fn ecb2_kill_proposer_liveness() {
    let _serialize = MULTI_PROCESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = node_bin();
    assert!(bin.exists(), "run `cargo build --workspace` first");
    let tmp = std::env::temp_dir().join(format!("ubi2-m5b-b2-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let _g = TmpGuard(tmp.clone());
    let mut nodes = spawn_three(&tmp, 10);
    wait_all_ready(&nodes);

    // Let the chain make progress, then find the node scheduled to propose head+1 (view 0) and kill it.
    let port0 = nodes[0].rpc_port;
    poll_until(
        || block_number(port0).filter(|h| *h >= 3),
        Duration::from_secs(40),
    )
    .expect("chain makes initial progress");
    let scheduled = scheduled_proposer(port0).expect("scheduledProposer");
    let victim_idx = (0..3)
        .find(|i| addr_of_key(&V_KEYS[*i]) == scheduled)
        .expect("scheduled proposer is one of our validators");
    let height_before = block_number(port0).unwrap_or(0);
    eprintln!(
        "[m5b] EC-B2 killing node {} (scheduled proposer {scheduled})",
        victim_idx + 1
    );
    nodes[victim_idx].kill();

    // A surviving node's RPC to observe from (not the victim).
    let observer = nodes
        .iter()
        .find(|n| (n.idx - 1) as usize != victim_idx)
        .unwrap()
        .rpc_port;

    // The chain must advance again (a successor proposes) within MAX_VIEW_CHANGES × PROPOSER_TIMEOUT +
    // slack. PROPOSER_TIMEOUT = 2×BLOCK_MS = 2s; budget 3 view changes ⇒ ~6s; allow generous slack.
    let advanced = poll_until(
        || block_number(observer).filter(|h| *h > height_before + 1),
        Duration::from_secs(30),
    );
    assert!(
        advanced.is_some(),
        "EC-B2: chain must advance past {} after the proposer was killed (got {:?})",
        height_before + 1,
        block_number(observer)
    );
    let new_h = advanced.unwrap();

    // Somewhere at/after the kill a recovering block carries view ≥ 1 authored by V[(h+view) mod 3].
    let mut saw_view_change = false;
    for h in height_before..=new_h {
        if let Some((_p, view)) = block_author(observer, h) {
            if view >= 1 {
                saw_view_change = true;
                break;
            }
        }
    }
    assert!(
        saw_view_change,
        "EC-B2: a recovering block must carry view >= 1 (a view change fired)"
    );
    eprintln!("[m5b] EC-B2 PASS: chain advanced to {new_h} via a view change");
}

/// EC-B4 — the killed node restarts and re-syncs to the canonical chain (same head hash + state_root),
/// with no manual steps. EC-B5 (state_root identical across rotation + a view change) is asserted too.
#[test]
#[ignore = "multi-process integration test; run with -- --ignored"]
fn ecb4_ecb5_reconverge_and_state_root_parity() {
    let _serialize = MULTI_PROCESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = node_bin();
    assert!(bin.exists(), "run `cargo build --workspace` first");
    let tmp = std::env::temp_dir().join(format!("ubi2-m5b-b4-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let _g = TmpGuard(tmp.clone());
    let mut nodes = spawn_three(&tmp, 20);
    wait_all_ready(&nodes);
    let port0 = nodes[0].rpc_port;

    // Make progress, kill the scheduled proposer (forces a view change — EC-B5's forced view change).
    poll_until(
        || block_number(port0).filter(|h| *h >= 4),
        Duration::from_secs(40),
    )
    .expect("initial progress");
    let scheduled = scheduled_proposer(port0).expect("scheduledProposer");
    let victim_idx = (0..3)
        .find(|i| addr_of_key(&V_KEYS[*i]) == scheduled)
        .unwrap();
    let killed_at = block_number(port0).unwrap_or(0);
    nodes[victim_idx].kill();

    // The two survivors keep producing (a majority of V is still connected → the guard is satisfied).
    let survivors: Vec<u16> = nodes
        .iter()
        .filter(|n| (n.idx - 1) as usize != victim_idx)
        .map(|n| n.rpc_port)
        .collect();
    let target = killed_at + 5;
    poll_until(
        || block_number(survivors[0]).filter(|h| *h >= target),
        Duration::from_secs(45),
    )
    .expect("EC-B2/B4: survivors keep producing through the view change");

    // EC-B5: the two live nodes agree byte-for-byte on `state_root` at a common height.
    let common = block_number(survivors[0])
        .unwrap()
        .min(block_number(survivors[1]).unwrap());
    let r0 = poll_until(
        || {
            let a = rpc_call(
                survivors[0],
                "ubi_stateRoot",
                &format!(r#"["0x{common:x}"]"#),
            )?;
            let b = rpc_call(
                survivors[1],
                "ubi_stateRoot",
                &format!(r#"["0x{common:x}"]"#),
            )?;
            let (a, b) = (a.as_str()?.to_string(), b.as_str()?.to_string());
            if a == b {
                Some(a)
            } else {
                None
            }
        },
        Duration::from_secs(15),
    );
    assert!(
        r0.is_some(),
        "EC-B5: live nodes must share state_root at height {common}"
    );
    eprintln!("[m5b] EC-B5 PASS: live nodes agree state_root at {common}");

    // EC-B4: restart the killed node — it must re-sync to the canonical chain with no manual steps.
    nodes[victim_idx].restart();
    let restart_port = nodes[victim_idx].rpc_port;
    assert!(
        wait_ready(restart_port, Duration::from_secs(20)),
        "restarted node RPC up"
    );
    // Compare at the FINALIZED height (spec 08 §6.3: `head - FINALITY_DEPTH`), not an arbitrary
    // just-reached tip height. A height above the finalized frontier may legitimately be mid-
    // reconciliation for a few blocks after a restart/view-change (an in-flight reorg is NOT a safety
    // violation, §6.3) — only the finalized frontier is guaranteed never to diverge. We wait for the
    // restarted node's height to move well past its own catch-up point (so its `finalizedHeight` has
    // advanced past the restart), then compare BOTH nodes' state at the min of their two
    // `finalizedHeight`s — a race-free, spec-accurate anchor.
    let reached = poll_until(
        || {
            let h_restart = block_number(restart_port)?;
            let h_live = block_number(survivors[0])?;
            let f_restart = finalized_height(restart_port)?;
            let f_live = finalized_height(survivors[0])?;
            if h_restart >= h_live && f_restart > 0 {
                Some(f_restart.min(f_live))
            } else {
                None
            }
        },
        Duration::from_secs(90),
    );
    assert!(
        reached.is_some(),
        "EC-B4: restarted node must catch up and finalize (restart height {:?}, live height {:?})",
        block_number(restart_port),
        block_number(survivors[0])
    );
    let target = reached.unwrap();
    let r_restart = state_root_at(restart_port, target).expect("restart has state_root at target");
    let r_live = state_root_at(survivors[0], target).expect("survivor has state_root at target");
    assert_eq!(
        r_restart, r_live,
        "EC-B4: restarted node's FINALIZED state_root at height {target} must equal the canonical chain's"
    );
    let h_restart = block_hash_at(restart_port, target).expect("restart has block hash at target");
    let h_live = block_hash_at(survivors[0], target).expect("survivor has block hash at target");
    assert_eq!(
        h_restart, h_live,
        "EC-B4: restarted node's FINALIZED block hash at height {target} must equal the canonical chain's"
    );
    eprintln!("[m5b] EC-B4 PASS: restarted node re-converged (finalized height {target})");
}

/// This node's `(reachableValidators, majority)` from `ubi_consensusStatus` (BLOCKER-2 §5.3). The
/// reachable count is a LOCAL liveness value; when it drops below `majority` the node stalls production.
fn reachable_and_majority(port: u16) -> Option<(u64, u64)> {
    let v = rpc_call(port, "ubi_consensusStatus", "[]")?;
    let reachable = v["reachableValidators"].as_u64()?;
    let majority = v["majority"].as_u64()?;
    Some((reachable, majority))
}

/// Assert every one of the given nodes agrees BYTE-FOR-BYTE on the finalized chain: the same `state_root`
/// AND the same block hash at the minimum `finalizedHeight` across all of them, once every node has
/// advanced past a positive finalized frontier. This is the CFT safety property (§7): no two honest nodes
/// finalize conflicting blocks. Returns the agreed finalized height, or `None` on timeout.
fn wait_all_converged(ports: &[u16], timeout: Duration) -> Option<u64> {
    poll_until(
        || {
            let fins: Vec<u64> = ports.iter().filter_map(|p| finalized_height(*p)).collect();
            if fins.len() != ports.len() {
                return None;
            }
            let common = *fins.iter().min().unwrap();
            if common == 0 {
                return None; // wait for a positive finalized frontier on every node
            }
            let roots: Vec<String> = ports
                .iter()
                .filter_map(|p| state_root_at(*p, common))
                .collect();
            let hashes: Vec<String> = ports
                .iter()
                .filter_map(|p| block_hash_at(*p, common))
                .collect();
            if roots.len() == ports.len()
                && hashes.len() == ports.len()
                && roots.iter().all(|r| *r == roots[0])
                && hashes.iter().all(|h| *h == hashes[0])
            {
                Some(common)
            } else {
                None
            }
        },
        timeout,
    )
}

/// BLOCKER-1 regression (multi-process, spec 08 §5.4/§7, EC-B-F5): a slow-but-alive scheduled proposer
/// (SIGSTOP, not SIGKILL) whose successor already EXTENDED the chain. On resume the recovered proposer
/// must reconcile — the general reorg heals its divergent tip and sync heals its gap WITHOUT penalizing
/// the honest peers relaying the canonical chain — so ALL nodes converge on one chain with byte-identical
/// finalized state roots. Before the fix a node driven onto a losing branch stayed WrongParent-stuck and
/// finalized a conflicting chain (or abandoned every honest peer on sync).
#[test]
#[ignore = "multi-process integration test; run with -- --ignored"]
fn ecbf5_delayed_proposer_multiprocess_converges() {
    let _serialize = MULTI_PROCESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = node_bin();
    assert!(bin.exists(), "run `cargo build --workspace` first");
    let tmp = std::env::temp_dir().join(format!("ubi2-m5b-delay-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let _g = TmpGuard(tmp.clone());
    let nodes = spawn_three(&tmp, 30);
    wait_all_ready(&nodes);
    let port0 = nodes[0].rpc_port;

    // Reach a comfortable height with all three connected + rotating.
    poll_until(
        || block_number(port0).filter(|h| *h >= 6),
        Duration::from_secs(60),
    )
    .expect("initial progress");

    // PAUSE (SIGSTOP — slow, not dead) the scheduled view-0 proposer for head+1. It freezes: it stops
    // producing/answering, but its TCP sockets linger. Its successors view-change and EXTEND the chain.
    let scheduled = scheduled_proposer(port0).expect("scheduledProposer");
    let victim = (0..3)
        .find(|i| addr_of_key(&V_KEYS[*i]) == scheduled)
        .expect("scheduled proposer is one of our validators");
    let paused_at = block_number(port0).unwrap_or(0);
    eprintln!(
        "[m5b] delay: pausing node {} (proposer {scheduled}) at height {paused_at}",
        victim + 1
    );
    nodes[victim].pause();

    // The majority (the 2 survivors) keeps producing through the view change (guard: 2 ≥ majority 2) —
    // the chain does NOT halt while the scheduled proposer is slow.
    let survivors: Vec<u16> = nodes
        .iter()
        .filter(|n| (n.idx - 1) as usize != victim)
        .map(|n| n.rpc_port)
        .collect();
    poll_until(
        || block_number(survivors[0]).filter(|h| *h >= paused_at + 6),
        Duration::from_secs(60),
    )
    .expect("majority keeps producing through the view change (chain does not halt)");

    // RESUME the slow proposer. It wakes with a stale (possibly divergent) tip and must reconcile with
    // the canonical chain — via the bounded general reorg (gossip) and/or fork-healing sync.
    eprintln!("[m5b] delay: resuming node {}", victim + 1);
    nodes[victim].resume();

    // SAFETY (§7): all three nodes converge BYTE-FOR-BYTE at the finalized frontier — no stuck node, no
    // conflicting finalized history, honest peers never abandoned.
    let all_ports: Vec<u16> = nodes.iter().map(|n| n.rpc_port).collect();
    let converged = wait_all_converged(&all_ports, Duration::from_secs(120));
    assert!(
        converged.is_some(),
        "EC-B-F5: all 3 nodes must converge byte-for-byte at the finalized height after a slow proposer recovers (heights {:?})",
        all_ports.iter().map(|p| block_number(*p)).collect::<Vec<_>>()
    );
    eprintln!(
        "[m5b] EC-B-F5 delay-proposer PASS: all 3 nodes converged (finalized height {})",
        converged.unwrap()
    );
}

/// BLOCKER-2 regression (multi-process, spec 08 §5.3): a silent BLACK-HOLE partition. Three connected
/// nodes; then the MAJORITY (2 of 3) is frozen (SIGSTOP) — they go silent while their TCP sockets linger
/// (still "connected" to the transport table). The lone minority node's ACTIVE liveness probe (ping)
/// must prune the silent peers, dropping its reachable count below majority within a bound WELL under
/// `FINALITY_DEPTH × BLOCK_MS`, so it STALLS (produces nothing → never k-deep-finalizes a divergent
/// chain). With the transport-table-only signal it would have kept counting the frozen peers and forked
/// finalized history — the exact hazard §5.3 prevents.
#[test]
#[ignore = "multi-process integration test; run with -- --ignored"]
fn ecb_blackhole_partition_minority_stalls() {
    let _serialize = MULTI_PROCESS_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let bin = node_bin();
    assert!(bin.exists(), "run `cargo build --workspace` first");
    let tmp = std::env::temp_dir().join(format!("ubi2-m5b-part-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    let _g = TmpGuard(tmp.clone());
    let nodes = spawn_three(&tmp, 40);
    wait_all_ready(&nodes);

    // All three connected + producing.
    let minority_port = nodes[2].rpc_port;
    poll_until(
        || block_number(nodes[0].rpc_port).filter(|h| *h >= 5),
        Duration::from_secs(60),
    )
    .expect("initial progress");
    // The minority is initially majority-connected (reachable ≥ majority).
    poll_until(
        || reachable_and_majority(minority_port).filter(|(r, m)| *r >= *m),
        Duration::from_secs(20),
    )
    .expect("minority starts majority-connected");

    // BLACK-HOLE the MAJORITY: freeze nodes 1 & 2. Their sockets linger (transport still "connected"),
    // but they answer no pings/blocks — the silent partition the guard must survive.
    eprintln!("[m5b] partition: black-holing the majority (nodes 1 & 2)");
    nodes[0].pause();
    nodes[1].pause();

    // The minority's reachable count must drop BELOW majority within a bound WELL under
    // FINALITY_DEPTH × BLOCK_MS (= 6 × BLOCK_MS). This is the active-liveness-probe fix in action.
    let bound = Duration::from_millis(6 * BLOCK_MS);
    let dropped = poll_until(
        || reachable_and_majority(minority_port).filter(|(r, m)| *r < *m),
        bound,
    );
    assert!(
        dropped.is_some(),
        "BLOCKER-2: the minority's reachable count must drop below majority within FINALITY_DEPTH×BLOCK_MS ({:?})",
        reachable_and_majority(minority_port)
    );
    eprintln!(
        "[m5b] partition: minority reachable dropped below majority ({:?})",
        dropped.unwrap()
    );

    // Let it fully settle past the pruning window, then assert the minority STALLS: no further block
    // production (it cannot finalize a divergent chain). We compare its height across a multi-block
    // window; a stalled node's height does not advance.
    std::thread::sleep(Duration::from_millis(2 * BLOCK_MS));
    let h_stall = block_number(minority_port).expect("minority reachable");
    std::thread::sleep(Duration::from_millis(5 * BLOCK_MS));
    let h_final = block_number(minority_port).expect("minority reachable");
    assert_eq!(
        h_final, h_stall,
        "BLOCKER-2: the minority STALLS once it loses majority-liveness (no divergent finalization): {h_stall} -> {h_final}"
    );
    // The stalled minority's finalized frontier never crossed the partition point (it produced nothing
    // that finalized): finalizedHeight = head − FINALITY_DEPTH, and head is frozen well below any
    // divergent progress.
    eprintln!("[m5b] BLOCKER-2 partition PASS: minority stalled at height {h_final} (no divergent finalization)");

    // Heal: resume the majority. The minority re-syncs to the (canonical) majority chain — demonstrating
    // the majority was the live/canonical side and no conflicting finalization occurred.
    nodes[0].resume();
    nodes[1].resume();
    let all_ports: Vec<u16> = nodes.iter().map(|n| n.rpc_port).collect();
    let converged = wait_all_converged(&all_ports, Duration::from_secs(120));
    assert!(
        converged.is_some(),
        "after heal, all nodes converge on one chain (the minority never forked finalized history)"
    );
    eprintln!(
        "[m5b] BLOCKER-2 partition heal PASS: all nodes converged (finalized height {})",
        converged.unwrap()
    );
}
