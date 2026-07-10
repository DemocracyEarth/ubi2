//! M5 Stage A — wiring `crates/network` (libp2p) into the node.
//!
//! This module owns the **glue** between the deterministic chain (`crates/rpc::Chain`) and the P2P
//! transport (`crates/network::NetworkHandle`/`NetEvent`). Stage A has ONE designated proposer and N
//! followers:
//!
//!   * **TX PATH (§3.2, validate-before-rebroadcast).** A tx arriving via gossip is validated with the
//!     SAME `ingest_raw_tx` path RPC uses (`Chain::ingest_gossip_tx`); only on success is it admitted +
//!     re-gossiped. An invalid tx is dropped (not forwarded) and the source peer penalized. (Locally
//!     submitted txs are relayed by the RPC `eth_sendRawTransaction` hook — see `serve` wiring in
//!     `main`.) gossipsub's message-id (= tx hash) dedups, so a relayed tx does not loop.
//!
//!   * **BLOCK PATH (§5.1, fail-closed).** The proposer produces blocks and broadcasts them; a follower
//!     receiving a block runs `Chain::validate_and_apply_block`, which checks the parent, the
//!     designated-proposer signature, and re-executes to a byte-identical `state_root`. On mismatch the
//!     block is REJECTED (no state change) and the peer penalized. Followers never produce blocks here.
//!
//!   * **SYNC (§4.2).** On a peer `Hello` whose tip is higher, the node pulls the missing `[from,to]`
//!     range (bounded by `SYNC_MAX_BATCH`), validates+applies each block from its current head, and then
//!     follows live gossip. A 4th node with empty state reaches the same tip + `state_root` with no
//!     manual steps.
//!
//! All async/libp2p lives in `crates/network`; this module only moves bytes through the
//! `NetworkHandle`/`NetEvent` seam and drives the chain.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use alloy_primitives::{Address as AlloyAddr, B256};
use libp2p::{Multiaddr, PeerId};
use ubi2_network::consts::{
    PROTOCOL_VERSION, SYNC_MAX_BATCH, SYNC_MAX_LOOKAHEAD, SYNC_MAX_NO_PROGRESS_ROUNDS,
};
use ubi2_network::wire::{Blocks, GetBlocks, Hello, WireBlock};
use ubi2_network::{NetEvent, NetworkHandle};
use ubi2_rpc::{BlockError, Chain, PeerStatus};

/// M5 Stage B (spec 08 §5.4): which follower-side block rejections are the peer's FAULT (a genuinely
/// invalid / forged block) versus a BENIGN fork-race artifact of CFT rotation (a block off our tip that
/// fork choice will reconcile). Only the former is penalized: a benign `WrongParent` / `NonContiguous`
/// / `BadTimestamp` block from an honest peer relaying the canonical chain must NOT be greylisted, or a
/// node stuck on a losing branch would abandon exactly the peers that could heal it (the Blocker-1 bug).
fn is_penalizable(err: &BlockError) -> bool {
    matches!(
        err,
        BlockError::WrongProposer
            | BlockError::BadSignature
            | BlockError::ViewOutOfRange { .. }
            | BlockError::StateRootMismatch { .. }
            | BlockError::NoValidatorSet
            | BlockError::UndecodableTx
    )
}

/// Per-peer state the node tracks (separate from the transport-level peer table in `crates/network`).
#[derive(Clone, Debug, Default)]
struct PeerEntry {
    multiaddr: Option<Multiaddr>,
    validator: Option<AlloyAddr>,
    tip: Option<(u64, B256)>,
    /// SEC-M5A-1: consecutive sync responses from this peer that made ZERO forward progress (applied 0).
    /// Reset on any forward progress. When it crosses [`SYNC_MAX_NO_PROGRESS_ROUNDS`] the peer is
    /// penalized + abandoned so a peer advertising a tip it cannot serve cannot drive an unbounded loop.
    sync_no_progress: u32,
    /// M5 Stage B (spec 08 §5.3): the last instant this peer was proven ALIVE — set on connect, on a
    /// successful `ping`, and on any authenticated inbound message (Hello / block / sync response). The
    /// production connectivity guard counts a `V`-member peer as reachable ONLY while this is fresh
    /// (`now − last_alive < LIVENESS_TIMEOUT`), so a silently-frozen/black-holed peer (whose TCP
    /// connection lingers for minutes) is pruned from "reachable" within a bound `≪ FINALITY_DEPTH ×
    /// BLOCK_MS`. A LOCAL liveness signal — it never enters a committed value (I1/I2).
    last_alive: Option<Instant>,
}

/// The node's network driver: holds the chain + handle + peer table and processes `NetEvent`s. One
/// instance runs on a single tokio task, so chain mutations are serialized (block production also runs
/// on this task in the proposer — see [`NetDriver::tick_proposer`]).
pub struct NetDriver {
    chain: Chain,
    handle: NetworkHandle,
    /// libp2p PeerId → what we know about the peer (its bound validator + last tip + addr).
    peers: HashMap<PeerId, PeerEntry>,
    /// This node's validator key (for the `Hello` peer-proof), if it is a validator.
    validator_key: Option<ubi2_network::ValidatorKey>,
    /// M5 Stage B (§3.3/§10): the Stage-A single-proposer OVERRIDE (only when `UBI2_DESIGNATED_PROPOSER`
    /// is explicitly configured). `Some(a)` ⇒ `V = [a]` (N=1) with precedence; `None` ⇒ the on-chain
    /// epoch snapshot governs the schedule (the multi-validator devnet).
    validator_override: Option<AlloyAddr>,
    /// True iff THIS node holds a proposer key (it MAY produce a block when the schedule elects it).
    is_proposer: bool,
    /// Highest tip we have already requested a sync up to, so we don't spam overlapping range pulls.
    sync_in_flight_to: u64,
    // ---- M5 Stage B: the LOCAL per-height view timer (§5.1) — wall-clock is LOCAL only, never committed.
    /// The height this node is currently trying to extend (`head + 1`); re-armed on every new head.
    view_height: u64,
    /// This node's local `current_view` for `view_height` (0 on a fresh head; incremented on timeout).
    current_view: u32,
    /// Monotonic deadline for the current view; on expiry with no block at `view_height`, escalate (§5.1).
    view_deadline: Instant,
    /// The local proposer timeout (`2 × BLOCK_MS`, §12) — how long to wait for the scheduled proposer.
    proposer_timeout: Duration,
    /// M5 Stage B (spec 08 §5.3): how long a peer's liveness stays "fresh" for the production guard. A
    /// `V`-member is counted reachable only while `now − last_alive < LIVENESS_TIMEOUT`. Set to
    /// `PROPOSER_TIMEOUT` (`2 × BLOCK_MS`): comfortably above the ping interval (a healthy peer refreshes
    /// several times over) yet far below `FINALITY_DEPTH × BLOCK_MS` (6× BLOCK_MS) — so a minority that
    /// loses majority-liveness stalls LONG before it could k-deep-finalize a divergent chain.
    liveness_timeout: Duration,
}

impl NetDriver {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain: Chain,
        handle: NetworkHandle,
        validator_key: Option<ubi2_network::ValidatorKey>,
        designated_proposer: Option<AlloyAddr>,
        validator_override: Option<AlloyAddr>,
        is_proposer: bool,
        block_ms: u64,
    ) -> Self {
        chain.set_proposer_role(is_proposer, designated_proposer);
        let proposer_timeout = Duration::from_millis(block_ms.saturating_mul(2).max(1));
        let driver = NetDriver {
            chain,
            handle,
            peers: HashMap::new(),
            validator_key,
            validator_override,
            is_proposer,
            sync_in_flight_to: 0,
            view_height: 0,
            current_view: 0,
            view_deadline: Instant::now() + proposer_timeout,
            proposer_timeout,
            // §5.3: liveness freshness window = PROPOSER_TIMEOUT (2×BLOCK_MS) ≪ FINALITY_DEPTH×BLOCK_MS.
            liveness_timeout: proposer_timeout,
        };
        driver.publish_consensus_status();
        driver
    }

    /// M5 Stage B (§5.3): mark a peer as proven-alive right now (on connect, a successful ping, or any
    /// authenticated inbound message). Keeps the production-guard "reachable" verdict fresh.
    fn mark_peer_alive(&mut self, peer: PeerId) {
        self.peers.entry(peer).or_default().last_alive = Some(Instant::now());
    }

    /// M5 Stage B (§11): publish the effective `V` + this node's local `current_view` + the reachable
    /// V-member count for `ubi_consensusStatus`. Called on start, on tip advance, on a view escalation,
    /// and whenever peer liveness changes. The reachable count is a LOCAL liveness value (never committed).
    fn publish_consensus_status(&self) {
        let v = self.chain.effective_validator_set(self.validator_override);
        let reachable = self.reachable_validator_count(&v);
        self.chain
            .set_consensus_status(v, self.current_view, reachable as u32);
    }

    /// M5 Stage B (spec 08 §5.3): the count of distinct `V`-members this node currently considers
    /// **reachable** — itself (if a validator in `V`) plus each bound-validator peer that is BOTH in `V`
    /// AND recently proven alive by the active liveness probe (`now − last_alive < LIVENESS_TIMEOUT`).
    ///
    /// The freshness gate is the Blocker-2 fix: reachability is derived from an ACTIVE liveness signal
    /// (libp2p `ping` + authenticated inbound traffic), NOT from the transport peer table alone — which
    /// only updates on TCP disconnect (minutes ≫ FINALITY_DEPTH×BLOCK_MS). A silently black-holed /
    /// frozen peer whose socket lingers is therefore pruned from "reachable" within
    /// `LIVENESS_TIMEOUT ≪ FINALITY_DEPTH×BLOCK_MS`, so a minority that loses majority-liveness stalls
    /// instead of finalizing a divergent chain. Pure of any committed value (I1/I2).
    fn reachable_validator_count(&self, v: &[AlloyAddr]) -> usize {
        if v.is_empty() {
            return 0;
        }
        let now = Instant::now();
        let vset: HashSet<AlloyAddr> = v.iter().copied().collect();
        let mut reachable: HashSet<AlloyAddr> = HashSet::new();
        // Count self if this node is a validator in `V` (always locally live).
        if let Some(me) = self.chain.proposer_address() {
            if vset.contains(&me) {
                reachable.insert(me);
            }
        }
        // Count each bound-validator peer in `V` that is FRESH by the active-liveness signal (§5.3).
        for e in self.peers.values() {
            if let Some(val) = e.validator {
                if !vset.contains(&val) {
                    continue;
                }
                let fresh = e
                    .last_alive
                    .is_some_and(|t| now.duration_since(t) < self.liveness_timeout);
                if fresh {
                    reachable.insert(val);
                }
            }
        }
        reachable.len()
    }

    /// M5 Stage B (§5.3): the production connectivity guard. This node may PRODUCE only when a **majority
    /// of `V`** (`N/2 + 1`, counting itself if it is a validator) is currently reachable *by the active
    /// liveness signal*. A minority partition therefore stalls (produces + finalizes nothing) rather than
    /// forking finalized history; on heal it re-syncs via fork choice. For `N = 1` the majority is 1
    /// (self) ⇒ Stage A is unaffected. This gates PRODUCTION only (a liveness policy); it never enters
    /// validation (a pure function).
    fn production_guard_ok(&self) -> bool {
        let v = self.chain.effective_validator_set(self.validator_override);
        let n = v.len();
        if n == 0 {
            return false;
        }
        let majority = n / 2 + 1;
        self.reachable_validator_count(&v) >= majority
    }

    /// Build the `Hello` this node advertises (called on start + after every tip advance).
    fn build_hello(&self) -> Hello {
        let (height, hash) = self.chain.tip();
        let genesis = self.chain.genesis_hash();
        let local_peer = self.handle.local_peer_id();
        let (validator, peer_proof) = match &self.validator_key {
            Some(vk) => {
                let digest = Hello::proof_digest(&local_peer.to_bytes(), &genesis);
                (Some(vk.address()), vk.sign_digest(&digest))
            }
            None => (None, Vec::new()),
        };
        Hello {
            genesis_hash: genesis,
            chain_id: self.chain.chain_id(),
            tip: (height, hash),
            validator,
            peer_proof,
            protocol_ver: PROTOCOL_VERSION,
        }
    }

    /// Push the freshly-built `Hello` to the swarm (advertised on new connections) + republish the live
    /// peer table for `ubi_getPeers`.
    fn refresh_advertised_state(&self) {
        self.handle.update_hello(self.build_hello());
        self.publish_peers();
        self.publish_consensus_status();
    }

    /// Publish the node's peer table into the chain so `ubi_getPeers` reads it (EC-1).
    fn publish_peers(&self) {
        let peers: Vec<PeerStatus> = self
            .peers
            .iter()
            .map(|(id, e)| PeerStatus {
                peer_id: id.to_base58(),
                multiaddr: e
                    .multiaddr
                    .as_ref()
                    .map(|a| a.to_string())
                    .unwrap_or_default(),
                validator: e.validator,
                tip: e.tip,
            })
            .collect();
        self.chain.set_peers(peers);
    }

    /// Process one inbound network event.
    pub fn on_event(&mut self, ev: NetEvent) {
        match ev {
            NetEvent::Listening { addr } => {
                tracing::info!(%addr, "p2p listening");
            }
            NetEvent::PeerConnected { peer, addr } => {
                let e = self.peers.entry(peer).or_default();
                e.multiaddr = Some(addr);
                // §5.3: a fresh connection is initial liveness evidence (until the first ping proves or
                // disproves it). Without this the guard would spuriously stall right after a reconnect.
                e.last_alive = Some(Instant::now());
                tracing::info!(%peer, "peer connected");
                self.publish_peers();
                self.publish_consensus_status();
            }
            NetEvent::PeerDisconnected { peer } => {
                self.peers.remove(&peer);
                tracing::info!(%peer, "peer disconnected");
                self.publish_peers();
            }
            NetEvent::PeerGreylisted { peer } => {
                self.peers.remove(&peer);
                tracing::warn!(%peer, "peer greylisted (too many invalid messages)");
                self.publish_peers();
            }
            NetEvent::Hello { peer, hello } => self.on_hello(peer, *hello),
            NetEvent::TxReceived { from, id, raw } => self.on_tx(from, id, raw),
            NetEvent::BlockReceived { from, block, .. } => self.on_block(from, *block),
            NetEvent::SyncRequest {
                from,
                request,
                token,
            } => self.on_sync_request(from, request, token),
            NetEvent::SyncResponse { from, blocks, .. } => self.on_sync_response(from, *blocks),
            NetEvent::PeerPing { peer, ok } => {
                // §5.3 active-liveness probe: a successful ping refreshes the peer's liveness (keeps it
                // in the production-guard reachable set); a failure/timeout is left to age out — once
                // `last_alive` is older than LIVENESS_TIMEOUT the peer is pruned from "reachable", so a
                // silently-frozen/black-holed peer stops counting toward majority within the bound.
                if ok {
                    self.mark_peer_alive(peer);
                    self.publish_consensus_status();
                }
            }
        }
    }

    /// §4.1 handshake: reject a wrong-network peer (genesis/chain mismatch ⇒ disconnect, AC-F7); record
    /// the PeerId↔validator binding; drive sync if the peer's tip is ahead.
    fn on_hello(&mut self, peer: PeerId, hello: Hello) {
        // Network-mismatch ⇒ disconnect immediately (cannot interoperate, AC-F7).
        if hello.genesis_hash != self.chain.genesis_hash()
            || hello.chain_id != self.chain.chain_id()
        {
            tracing::warn!(%peer, "wrong-network peer (genesis/chain mismatch) — disconnecting");
            self.handle.disconnect(peer);
            self.peers.remove(&peer);
            self.publish_peers();
            return;
        }
        // M5 Stage B (§9): protocol-version compatibility. A peer whose major protocol version differs
        // speaks a different block encoding (Stage B added the header `view`), so it is INCOMPATIBLE —
        // disconnect at the handshake rather than silently mis-decode its blocks. This makes the wire
        // change a loud, explicit break (alongside the genesis/chain check above).
        if hello.protocol_ver != PROTOCOL_VERSION {
            tracing::warn!(
                %peer, peer_ver = hello.protocol_ver, local_ver = PROTOCOL_VERSION,
                "incompatible protocol version — disconnecting"
            );
            self.handle.disconnect(peer);
            self.peers.remove(&peer);
            self.publish_peers();
            return;
        }
        let bound = hello.verify_binding(&peer.to_bytes());
        // SEC-M5A-1: a `Hello.tip` is peer-advertised and UNAUTHENTICATED — a hostile peer can claim any
        // height. We record it for `ubi_getPeers`, but we only chase it if it is plausibly ahead (within
        // SYNC_MAX_LOOKAHEAD of our head). An implausibly-far tip (e.g. u64::MAX) is logged and ignored
        // for sync; it is never pinned as a target. A genuinely far-behind node still catches up because
        // each applied batch re-bounds the next acceptable look-ahead.
        let entry = self.peers.entry(peer).or_default();
        entry.validator = bound;
        entry.tip = Some(hello.tip);
        // §5.3: a received Hello proves the peer is alive right now (refreshes the guard freshness).
        entry.last_alive = Some(Instant::now());
        if let Some(v) = bound {
            tracing::info!(%peer, validator = %v, tip = hello.tip.0, "peer hello (validator bound)");
        } else {
            tracing::debug!(%peer, tip = hello.tip.0, "peer hello (non-validator / unbound)");
        }
        self.publish_peers();
        self.maybe_sync(peer, hello.tip.0);
    }

    /// §3.2 tx gossip: validate-before-rebroadcast. Dedup at the chain level, validate via the same
    /// `ingest_raw_tx` path RPC uses, and only re-gossip on success. Invalid ⇒ drop + penalize.
    fn on_tx(&mut self, from: PeerId, id: B256, raw: Vec<u8>) {
        if self.chain.knows_tx(&id) {
            return; // already in mempool or mined — do not re-validate/re-forward (no loop)
        }
        match self.chain.ingest_gossip_tx(&raw) {
            Ok(_hash) => {
                // Admitted ⇒ relay to the rest of the mesh (gossipsub dedups by message-id, so this does
                // not loop back to `from`).
                self.handle.publish_tx(raw);
            }
            Err(e) => {
                tracing::debug!(%from, error = %e, "dropping invalid gossiped tx; penalizing peer");
                self.handle.penalize_peer(from);
            }
        }
    }

    /// §5.1 block validation (fail-closed) + §5.4/§6 fork-choice reorg. A follower re-executes + matches
    /// the `state_root`; the proposer ignores its own echoed blocks (it produced them). On a clean
    /// extension it accepts + relays; on a benign fork-race block (a competitor at the tip, or a child of
    /// a not-yet-canonical block) it routes to the bounded GENERAL reorg (never penalizing the honest
    /// relayer); only a genuinely-invalid block (bad view/signature/proposer/state-root) is penalized.
    fn on_block(&mut self, from: PeerId, block: WireBlock) {
        // §5.3: receiving a valid gossiped block proves the sender is alive (transport-verified by the
        // network layer's shallow_verify before it reaches here).
        self.mark_peer_alive(from);
        let (local_h, _local_hash) = self.chain.tip();
        let block_hash = block.hash();
        // Already canonical (our tip or an interior block) — dedup, nothing to do.
        if self.chain.knows_block(&block_hash) {
            return;
        }

        // The common path: a clean extension of our current tip.
        if block.number == local_h + 1 {
            match self.apply_wire_block(&block) {
                Ok(()) => {
                    tracing::info!(
                        number = block.number,
                        txs = block.txs.len(),
                        "applied gossiped block"
                    );
                    self.peers.entry(from).or_default().tip = Some((block.number, block_hash));
                    self.handle.publish_block(block);
                    self.refresh_advertised_state();
                    return;
                }
                Err(e) if is_penalizable(&e) => {
                    tracing::warn!(%from, number = block.number, error = %e, "rejecting block; penalizing peer");
                    self.handle.penalize_peer(from);
                    return;
                }
                Err(_) => {
                    // WrongParent / NonContiguous / BadTimestamp: a BENIGN fork-race child (its parent is
                    // not our tip). Fall through to the general fork-choice reorg — do NOT penalize.
                }
            }
        }

        // A block beyond head+1 we cannot yet link (a gap). Retain it in the side store (it may complete
        // a branch once its ancestors arrive) AND drive sync to fetch the gap — but only after the
        // SEC-M5A-1 trust gate, so a forged/untrusted ahead-announcement cannot pin a bogus tip.
        if block.number > local_h + 1 {
            if !self.announced_tip_is_trustworthy(&block) {
                tracing::warn!(
                    %from, number = block.number,
                    "ignoring untrusted ahead-block announcement (unsigned / wrong proposer); not pinning tip"
                );
                self.handle.penalize_peer(from);
                return;
            }
            self.consider_fork(from, &block);
            self.peers.entry(from).or_default().tip = Some((block.number, block_hash));
            self.maybe_sync(from, block.number);
            return;
        }

        // Otherwise: a competing / divergent block AT or BELOW our tip height (a tip race, or a fork
        // branch block). Route it to the bounded GENERAL reorg (§5.4/§6.1): reorg iff it completes a
        // strictly fork-choice-preferred branch back to a common ancestor above the finalized frontier.
        self.consider_fork(from, &block);
    }

    /// M5 Stage B (spec 08 §5.4/§6.1/§6.3): feed a benign fork-race / non-contiguous block into the
    /// bounded GENERAL reorg. `consider_competing_block` authenticates + retains it in the side store and
    /// reorgs iff it completes a strictly-preferred, finality-safe branch. On a reorg we relay the block
    /// and re-advertise our new tip; a valid-but-not-adopted block is simply retained (NOT penalized —
    /// it is a normal CFT tip race); only a GENUINELY invalid block (bad view/signature/proposer/root)
    /// is penalized.
    fn consider_fork(&mut self, from: PeerId, block: &WireBlock) {
        match self.chain.consider_competing_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.view,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &block.txs,
            self.validator_override,
        ) {
            Ok(Some(applied)) => {
                tracing::info!(
                    number = applied.number,
                    view = applied.view,
                    "reorged to fork-choice-preferred branch (bounded general reorg)"
                );
                self.chain.cache_raw_txs(&block.txs);
                self.peers.entry(from).or_default().tip = Some((block.number, block.hash()));
                self.handle.publish_block(block.clone());
                self.refresh_advertised_state();
            }
            Ok(None) => {
                // Valid but not adopted (current chain still preferred, branch incomplete, or
                // finality-bounded) — retained in the side store for later. Benign: do NOT penalize.
            }
            Err(e) if is_penalizable(&e) => {
                tracing::debug!(%from, number = block.number, error = %e, "fork block genuinely invalid; penalizing peer");
                self.handle.penalize_peer(from);
            }
            Err(e) => {
                tracing::debug!(%from, number = block.number, error = %e, "fork block not adoptable (benign)");
            }
        }
    }

    /// SEC-M5A-1: may we trust an ahead-of-head block ANNOUNCEMENT for its NUMBER (i.e. pin it as a sync
    /// target)? Only if it is authenticated by the Stage-A designated proposer: a valid `txs_root` + a
    /// valid proposer signature (`shallow_verify`) AND the block's `proposer` equals our designated
    /// proposer. We cannot re-execute it here (we are missing its parents), so this authorship check is
    /// the gate that stops a forged/unsigned/wrong-proposer block pinning a bogus tip. The look-ahead
    /// distance bound is enforced separately in `maybe_sync`.
    fn announced_tip_is_trustworthy(&self, block: &WireBlock) -> bool {
        if !block.shallow_verify() {
            return false; // unsigned or txs_root/sig mismatch — never trust its number
        }
        // Stage B: the announced author must be a plausible validator. In the Stage-A override that is
        // the single designated proposer; in the multi-validator mode it is any member of the effective
        // `V` (the on-chain epoch snapshot). We cannot re-execute an ahead-block here (we lack its
        // parents), so this membership check is the gate that stops a forged/wrong-author block pinning a
        // bogus tip; the schedule/re-execution is re-checked on the sync-applied path.
        let v = self.chain.effective_validator_set(self.validator_override);
        if v.is_empty() {
            // No set resolvable (single-node devnet with no seeded validators) — fail closed.
            return false;
        }
        v.contains(&block.proposer)
    }

    /// Validate + apply one wire block against the local head (the shared follower path used by both live
    /// gossip and sync). Caches the block's raw txs so this node can later re-serve them on sync. Returns
    /// the typed [`BlockError`] so the caller can distinguish a benign fork-race rejection (route to the
    /// general reorg) from a genuinely-invalid block (penalize) via [`is_penalizable`].
    fn apply_wire_block(&self, block: &WireBlock) -> Result<(), BlockError> {
        self.chain.validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.view,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &block.txs,
            self.validator_override,
        )?;
        self.chain.cache_raw_txs(&block.txs);
        Ok(())
    }

    /// §4.2 sync server: answer a `[from,to]` range request, clamped to `SYNC_MAX_BATCH`, in ascending
    /// height order, from this node's persisted blocks.
    fn on_sync_request(
        &mut self,
        from: PeerId,
        request: GetBlocks,
        token: ubi2_network::SyncResponder,
    ) {
        let (head, _) = self.chain.tip();
        let start = request.from.max(1); // genesis (height 0) is reconstructed by seeding, never served
        let end = request
            .to
            .min(head)
            .min(start.saturating_add(SYNC_MAX_BATCH - 1));
        let mut blocks = Vec::new();
        if start <= end {
            for h in start..=end {
                if let Some(b) = self.chain.block_at(h) {
                    blocks.push(self.wire_block_from(&b));
                }
            }
        }
        tracing::debug!(%from, from = request.from, to = request.to, served = blocks.len(), "served sync");
        self.handle.respond_blocks(token, Blocks { blocks });
    }

    /// §4.2 sync client + §5.4/§6.3 fork healing. Apply a received batch in ascending order. A block that
    /// cleanly extends our tip is applied; a block that DIVERGES from our chain (WrongParent — the peer
    /// is on a different, possibly-canonical branch) is NOT a reason to abandon an honest peer (the
    /// Blocker-1 bug) — it is routed to the bounded GENERAL reorg (retained + maybe reorged). If the
    /// batch reveals a fork we could not yet complete, we BACKFILL the peer's divergent ancestors (from
    /// just above the finalized frontier) so the side store can complete the branch and reorg. Only a
    /// GENUINELY-invalid block (bad view/signature/proposer/state-root) or a stuck no-progress peer is
    /// penalized (AC-F8).
    fn on_sync_response(&mut self, from: PeerId, resp: Blocks) {
        // §5.3: a sync response proves the peer is alive.
        self.mark_peer_alive(from);
        let head_before = self.chain.tip().0;
        let mut fork_seen = false;

        for block in &resp.blocks {
            let (head, _) = self.chain.tip();
            let bh = block.hash();
            // Dedup: a block already in our canonical chain (a shared prefix / overlapping batch).
            if self.chain.knows_block(&bh) {
                continue;
            }
            // Transport sanity: a sync block must carry a valid txs_root + a recovering signature.
            if !block.shallow_verify() {
                tracing::warn!(%from, number = block.number, "sync block failed shallow-verify; abandoning peer");
                self.handle.penalize_peer(from);
                break;
            }
            // Fast path: a clean extension of our tip (before we switch to fork mode for this batch).
            if !fork_seen && block.number == head + 1 {
                match self.apply_wire_block(block) {
                    Ok(()) => continue,
                    Err(e) if is_penalizable(&e) => {
                        tracing::warn!(%from, number = block.number, error = %e, "sync block invalid; abandoning peer");
                        self.handle.penalize_peer(from);
                        break;
                    }
                    // WrongParent / NonContiguous: the peer's chain diverges from ours — a FORK, not a
                    // fault. Switch to fork mode and route this (and the rest of the batch) to the general
                    // reorg; an honest peer relaying the canonical chain is NEVER penalized for this.
                    Err(_) => fork_seen = true,
                }
            }
            // Fork mode (or a below-tip divergent block): retain + maybe reorg via the general path.
            self.consider_fork(from, block);
        }

        // The in-flight pull has resolved; allow a follow-up request.
        self.sync_in_flight_to = 0;
        let head_after = self.chain.tip().0;
        let progressed = head_after > head_before;

        if progressed {
            tracing::info!(%from, tip = head_after, "applied sync batch (or healed a fork by reorg)");
            // Forward progress: reset the no-progress counter and chase the next batch toward the tip.
            if let Some(e) = self.peers.get_mut(&from) {
                e.sync_no_progress = 0;
            }
            self.refresh_advertised_state();
            if let Some(peer_tip) = self.peers.get(&from).and_then(|e| e.tip).map(|(h, _)| h) {
                self.maybe_sync(from, peer_tip);
            }
            return;
        }

        // SEC-M5A-1: NO forward progress. Re-issuing a range pull unconditionally produces an UNBOUNDED
        // loop against a peer that cannot serve a linkable chain. Count no-progress rounds and, past the
        // bound, PENALIZE + abandon the peer.
        let rounds = {
            let e = self.peers.entry(from).or_default();
            e.sync_no_progress = e.sync_no_progress.saturating_add(1);
            e.sync_no_progress
        };
        if rounds >= SYNC_MAX_NO_PROGRESS_ROUNDS {
            tracing::warn!(
                %from, rounds,
                "sync made no progress for too many rounds; penalizing + abandoning peer (no re-request)"
            );
            self.handle.penalize_peer(from);
            if let Some(e) = self.peers.get_mut(&from) {
                e.tip = None;
            }
            return;
        }
        // Bounded retry. If this batch revealed a FORK we could not yet complete, BACKFILL the peer's
        // divergent ancestors (from just above the finalized frontier) so the side store can complete the
        // branch back to a common ancestor and heal it by a bounded general reorg (§5.4/§6.3) — instead
        // of abandoning the honest peer. Otherwise retry toward the recorded tip.
        if fork_seen {
            self.request_fork_backfill(from);
        } else if let Some(peer_tip) = self.peers.get(&from).and_then(|e| e.tip).map(|(h, _)| h) {
            tracing::debug!(%from, rounds, "sync made no progress; bounded retry");
            self.maybe_sync(from, peer_tip);
        }
    }

    /// M5 Stage B (spec 08 §5.4/§6.3): when a sync batch reveals the peer is on a DIFFERENT branch (a
    /// fork), pull the peer's blocks from just above the finalized frontier down to our head so the
    /// divergent ANCESTORS arrive. Combined with the divergent descendants already retained from the
    /// batch, the side store can then complete the branch back to a common ancestor and heal the fork by
    /// a bounded general reorg. Bounded by `SYNC_MAX_BATCH`; the no-progress counter caps re-issue so a
    /// peer that cannot actually complete the branch is eventually abandoned.
    fn request_fork_backfill(&mut self, peer: PeerId) {
        let head = self.chain.tip().0;
        let finalized = self.chain.finalized_height();
        let from = finalized.saturating_add(1).max(1);
        if from > head {
            return; // nothing below the tip to backfill (fork must be at/below finalized — refuse it)
        }
        let to = head.min(from + SYNC_MAX_BATCH - 1);
        tracing::info!(%peer, from, to, "fork detected on sync; backfilling divergent ancestors for a bounded reorg");
        self.handle.request_blocks(peer, GetBlocks { from, to });
    }

    /// Request the missing range from `peer` if its `peer_tip` is ahead of our head and we don't already
    /// have an overlapping pull in flight.
    ///
    /// SEC-M5A-1: refuse to chase an implausibly-far advertised tip. A hostile peer can claim any height
    /// (an unauthenticated `Hello.tip`, or a forged ahead-block number). We only sync toward a tip within
    /// SYNC_MAX_LOOKAHEAD of our head; anything further is ignored (not pinned as a target). Each applied
    /// batch advances `head`, which re-bounds the next acceptable look-ahead, so a genuinely far-behind
    /// node still converges — it just cannot be slingshotted to u64::MAX in one step.
    fn maybe_sync(&mut self, peer: PeerId, peer_tip: u64) {
        let (head, _) = self.chain.tip();
        if peer_tip <= head {
            return;
        }
        if peer_tip > head.saturating_add(SYNC_MAX_LOOKAHEAD) {
            tracing::warn!(
                %peer, peer_tip, head,
                "ignoring implausibly-far advertised tip (> SYNC_MAX_LOOKAHEAD ahead); not chasing it"
            );
            return;
        }
        if peer_tip <= self.sync_in_flight_to {
            return; // already pulling up to (at least) this height
        }
        let from = head + 1;
        let to = peer_tip.min(from + SYNC_MAX_BATCH - 1);
        self.sync_in_flight_to = to;
        tracing::info!(%peer, from, to, "requesting sync range");
        self.handle.request_blocks(peer, GetBlocks { from, to });
    }

    /// Map an `rpc::Block` to a gossipable `WireBlock` (raw user txs pulled from the chain's raw cache).
    fn wire_block_from(&self, b: &ubi2_rpc::Block) -> WireBlock {
        WireBlock {
            number: b.number,
            parent_hash: b.parent_hash,
            timestamp: b.timestamp,
            view: b.view,
            txs_root: b.txs_root,
            state_root: b.state_root,
            proposer: b.proposer,
            proposer_sig: b.proposer_sig.clone(),
            txs: self.chain.raw_txs_for_block(b),
        }
    }

    /// M5 Stage B (§5.1) — the per-tick consensus step every validator node runs on the block interval:
    /// advance the LOCAL view timer, and PRODUCE a block iff this node is the scheduled proposer for
    /// `(head+1, current_view)` AND the production connectivity guard (§5.3) holds. Returns the produced
    /// block (for persist/log) or `None`. Wall-clock (`Instant`) is used ONLY for the view deadline; the
    /// block's committed timestamp is `timestamp` (the caller's clock), and the schedule/validity read no
    /// clock — so a clock-skewed node still agrees block-for-block on what is valid (I1/I2).
    ///
    /// Back-compat (Stage A / N=1): the sole validator is always `proposer(h, v)`, the guard's
    /// `majority = 1` is met by self, and it produces every block at `view 0` — exactly Stage A.
    pub fn tick_proposer(&mut self, timestamp: u64) -> Option<ubi2_rpc::Block> {
        let (head, _) = self.chain.tip();
        let target = head + 1;
        // Re-arm the local view timer on a new head (adopted by production or by applying a block).
        if self.view_height != target {
            self.view_height = target;
            self.current_view = 0;
            self.view_deadline = Instant::now() + self.proposer_timeout;
            self.publish_consensus_status();
        } else if Instant::now() >= self.view_deadline {
            // §5.1 timeout: no valid block at `target` by the deadline — escalate to the next view. The
            // successor is authorized purely by the schedule (§5.2); no view-change message is sent.
            self.current_view = self.current_view.saturating_add(1);
            self.view_deadline = Instant::now() + self.proposer_timeout;
            tracing::info!(
                height = target,
                view = self.current_view,
                "view timeout — escalating"
            );
            self.publish_consensus_status();
        }
        // §5.3: refresh the reachable-validator count every tick so it AGES as peer liveness changes
        // (a frozen/black-holed peer stops refreshing `last_alive` → drops out of "reachable"), keeping
        // `ubi_consensusStatus.reachableValidators` live for the partition observer.
        self.publish_consensus_status();

        // A node with no proposer key can never produce (a pure follower).
        if !self.is_proposer {
            return None;
        }
        // Am I the scheduled proposer for (target, current_view)?
        let me = self.chain.proposer_address();
        let scheduled =
            self.chain
                .scheduled_proposer(target, self.current_view, self.validator_override);
        if me.is_none() || scheduled.is_none() || me != scheduled {
            return None;
        }
        // §5.3 production connectivity guard: only produce when connected to a majority of `V`.
        if !self.production_guard_ok() {
            tracing::debug!(
                height = target,
                view = self.current_view,
                "scheduled, but production guard not met (not majority-connected) — not producing"
            );
            return None;
        }
        let block = self
            .chain
            .produce_block_at_view(timestamp, self.current_view);
        let wire = self.wire_block_from(&block);
        self.handle.publish_block(wire);
        // We just extended to `target`; the next tick re-arms the view timer for `target + 1`.
        self.refresh_advertised_state();
        Some(block)
    }

    /// Relay any locally-submitted mempool txs to the mesh (EC-2). `eth_sendRawTransaction` admits a tx
    /// straight into the mempool without touching this task, so we re-publish the current pending set on
    /// a short timer; gossipsub dedups by tx-hash message-id, so an already-gossiped tx is a no-op.
    pub fn relay_pending_txs(&self) {
        for raw in self.chain.pending_raw_txs() {
            self.handle.publish_tx(raw);
        }
    }

    /// Advertise our initial `Hello` + peer table at startup (before any block is produced).
    pub fn announce_start(&self) {
        self.refresh_advertised_state();
    }

    // ---- test-only accessors (SEC-M5A-1 regression: the no-progress sync loop is BOUNDED) ----
    #[cfg(test)]
    fn test_set_peer_tip(&mut self, peer: PeerId, tip: (u64, B256)) {
        self.peers.entry(peer).or_default().tip = Some(tip);
    }
    #[cfg(test)]
    fn test_peer_tip(&self, peer: &PeerId) -> Option<(u64, B256)> {
        self.peers.get(peer).and_then(|e| e.tip)
    }
    #[cfg(test)]
    fn test_peer_no_progress(&self, peer: &PeerId) -> u32 {
        self.peers
            .get(peer)
            .map(|e| e.sync_no_progress)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod sync_loop_tests {
    use super::*;
    use ubi2_network::config::NetworkConfig;
    use ubi2_rpc::Chain;

    /// Build a `NetDriver` over a real (but standalone) network handle for unit-testing the sync-driver
    /// logic. The swarm loop is spawned by `start`, but these tests never connect a peer — they drive
    /// `on_sync_response` directly and assert the driver's own bookkeeping (tip pinning / no-progress
    /// counting), which is where the SEC-M5A-1 loop bound lives.
    fn test_driver(rt: &tokio::runtime::Runtime) -> (NetDriver, PeerId) {
        let chain = Chain::new(ubi2_rpc::DEVNET_CHAIN_ID, 1_000);
        let cfg = NetworkConfig::new(ubi2_rpc::DEVNET_CHAIN_ID, chain.genesis_hash());
        let (handle, _rx) = rt.block_on(async { ubi2_network::start(cfg).unwrap() });
        let designated = Some(AlloyAddr::repeat_byte(0xDD));
        let driver = NetDriver::new(chain, handle, None, designated, designated, false, 2_000);
        (driver, PeerId::random())
    }

    /// SEC-M5A-1: a peer advertising a tip it cannot serve (every sync response is empty) must NOT drive
    /// an unbounded re-request loop. After `SYNC_MAX_NO_PROGRESS_ROUNDS` no-progress responses the driver
    /// PENALIZES the peer and CLEARS its recorded tip, so subsequent `maybe_sync` stops targeting it.
    #[test]
    fn empty_responses_bound_the_loop_and_clear_the_tip() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut driver, peer) = test_driver(&rt);
        // Pin a forged-far tip (the SEC-M5A-1 scenario), then feed empty responses.
        driver.test_set_peer_tip(peer, (u64::MAX, B256::ZERO));

        for round in 1..SYNC_MAX_NO_PROGRESS_ROUNDS {
            driver.on_sync_response(peer, Blocks { blocks: vec![] });
            assert_eq!(
                driver.test_peer_no_progress(&peer),
                round,
                "no-progress counter increments each empty round"
            );
            assert!(
                driver.test_peer_tip(&peer).is_some(),
                "tip still pinned during the bounded-retry window"
            );
        }
        // The round that crosses the bound clears the tip + penalizes — the loop terminates.
        driver.on_sync_response(peer, Blocks { blocks: vec![] });
        assert_eq!(
            driver.test_peer_tip(&peer),
            None,
            "SEC-M5A-1: after the no-progress bound the peer's tip is cleared (no more re-requesting)"
        );

        rt.shutdown_background();
    }

    /// SEC-M5A-1: `maybe_sync` refuses to chase a tip beyond `SYNC_MAX_LOOKAHEAD` of the local head — a
    /// forged u64::MAX tip never sets `sync_in_flight_to`, so no range request is issued for it.
    #[test]
    fn maybe_sync_ignores_implausibly_far_tip() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (mut driver, peer) = test_driver(&rt);
        // Local head is genesis (0). An implausibly-far tip must be ignored (no in-flight target set).
        driver.maybe_sync(peer, u64::MAX);
        assert_eq!(
            driver.sync_in_flight_to, 0,
            "an implausibly-far tip must not arm a sync request (SEC-M5A-1)"
        );
        // A plausibly-ahead tip (within the look-ahead) DOES arm a bounded request.
        driver.maybe_sync(peer, 10);
        assert!(
            driver.sync_in_flight_to > 0,
            "a plausibly-ahead tip arms a bounded sync request"
        );

        rt.shutdown_background();
    }
}

/// BLOCKER-2 (spec 08 §5.3): the production connectivity guard must derive "reachable" from the ACTIVE
/// liveness signal (ping / recent authenticated traffic), NOT from the transport peer table alone —
/// which only updates on TCP disconnect (minutes ≫ FINALITY_DEPTH×BLOCK_MS). These tests drive the
/// guard directly: a silently-black-holed / frozen V-member (still in the peer table, but no fresh
/// liveness) is pruned from "reachable" within `LIVENESS_TIMEOUT`, so a minority that loses
/// majority-liveness STALLS instead of finalizing a divergent chain.
#[cfg(test)]
mod liveness_guard_tests {
    use super::*;
    use std::sync::Arc;
    use std::time::Duration;
    use ubi2_network::config::NetworkConfig;
    use ubi2_rpc::{Chain, ProposerKey, DEVNET_CHAIN_ID};
    use ubi2_runtime::{Account, UBI};

    // The 3 devnet validator keys (Anvil #1..#3 — PUBLIC keys, not secrets).
    const V_KEYS_HEX: [&str; 3] = [
        "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
        "5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a",
        "7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6",
    ];
    const GENESIS_TIME: u64 = 1_700_000_000;

    fn key_bytes(h: &str) -> [u8; 32] {
        let b = h.as_bytes();
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (b[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (b[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *slot = (hi << 4) | lo;
        }
        out
    }

    /// A 3-validator seeded chain (on-chain `V = {v1, v2, v3}`) whose proposer key is `my_key` (one of
    /// the three), configured for the multi-validator path (no single-proposer override).
    fn seeded_3v_chain(my_key: [u8; 32]) -> (Chain, Vec<AlloyAddr>) {
        let chain = Chain::new(DEVNET_CHAIN_ID, GENESIS_TIME)
            .with_proposer_key(Arc::new(ProposerKey::from_bytes(&my_key).unwrap()));
        for hx in &V_KEYS_HEX {
            let addr = ProposerKey::from_bytes(&key_bytes(hx)).unwrap().address();
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
        let v = chain.validator_set();
        (chain, v)
    }

    fn driver_for(rt: &tokio::runtime::Runtime, my_key: [u8; 32], block_ms: u64) -> NetDriver {
        let (chain, _v) = seeded_3v_chain(my_key);
        let cfg = NetworkConfig::new(DEVNET_CHAIN_ID, chain.genesis_hash());
        let (handle, _rx) = rt.block_on(async { ubi2_network::start(cfg).unwrap() });
        // Multi-validator mode: no designated proposer, no override; this node holds a proposer key.
        NetDriver::new(chain, handle, None, None, None, true, block_ms)
    }

    /// BLOCKER-2: the guard counts a V-member as reachable ONLY while its active-liveness signal is
    /// fresh. A frozen/black-holed peer (still in the table, but no fresh liveness) is pruned within
    /// `LIVENESS_TIMEOUT`, dropping a lone node below majority so it STALLS — the exact partition-safety
    /// the transport-table-only signal could not provide.
    #[test]
    fn guard_prunes_black_holed_peers_and_stalls_the_minority() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Small block interval ⇒ LIVENESS_TIMEOUT = 2×BLOCK_MS = 400ms (fast, non-flaky test).
        let block_ms = 200u64;
        let mut driver = driver_for(&rt, key_bytes(V_KEYS_HEX[0]), block_ms);
        let v = driver.chain.effective_validator_set(None);
        assert_eq!(v.len(), 3, "on-chain V has 3 validators");
        let majority = v.len() / 2 + 1; // 2
        let me = driver.chain.proposer_address().unwrap();
        let others: Vec<AlloyAddr> = v.iter().copied().filter(|a| *a != me).collect();
        assert_eq!(others.len(), 2);

        // Self-only: reachable = 1 < majority ⇒ the guard STALLS (a minority cannot finalize).
        assert_eq!(driver.reachable_validator_count(&v), 1);
        assert!(
            !driver.production_guard_ok(),
            "self-only is a minority; production must be gated off"
        );

        // Two bound-validator peers, FRESH (recently proven alive) ⇒ reachable = 3 ⇒ guard satisfied.
        let now = Instant::now();
        let p2 = PeerId::random();
        let p3 = PeerId::random();
        driver.peers.insert(
            p2,
            PeerEntry {
                validator: Some(others[0]),
                last_alive: Some(now),
                ..Default::default()
            },
        );
        driver.peers.insert(
            p3,
            PeerEntry {
                validator: Some(others[1]),
                last_alive: Some(now),
                ..Default::default()
            },
        );
        assert_eq!(
            driver.reachable_validator_count(&v),
            3,
            "self + 2 fresh bound-validator peers are all reachable"
        );
        assert!(
            driver.production_guard_ok(),
            "majority-connected ⇒ may produce"
        );

        // BLACK HOLE: the two peers go SILENT (frozen) but their entries LINGER in the table (TCP still
        // 'connected'). After LIVENESS_TIMEOUT with no fresh liveness they must be pruned from
        // 'reachable' — the Blocker-2 fix (the transport-table-only signal would keep counting them).
        std::thread::sleep(Duration::from_millis(block_ms * 2 + 150));
        assert!(
            driver.peers.contains_key(&p2) && driver.peers.contains_key(&p3),
            "the black-holed peers are STILL in the transport table (not disconnected)"
        );
        assert_eq!(
            driver.reachable_validator_count(&v),
            1,
            "BLOCKER-2: silently-black-holed peers are pruned from reachable within LIVENESS_TIMEOUT"
        );
        assert!(
            !driver.production_guard_ok(),
            "BLOCKER-2: the minority now STALLS (reachable < majority) — no divergent finalization"
        );

        // A fresh ping from one peer restores it to reachable (majority regained ⇒ may produce again).
        driver.mark_peer_alive(p2);
        assert_eq!(driver.reachable_validator_count(&v), 2);
        assert!(
            driver.production_guard_ok(),
            "a re-proven-alive majority restores production"
        );
        let _ = majority;
        rt.shutdown_background();
    }
}
