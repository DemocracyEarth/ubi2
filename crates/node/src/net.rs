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

use std::collections::HashMap;

use alloy_primitives::{Address as AlloyAddr, B256};
use libp2p::{Multiaddr, PeerId};
use ubi2_network::consts::{
    PROTOCOL_VERSION, SYNC_MAX_BATCH, SYNC_MAX_LOOKAHEAD, SYNC_MAX_NO_PROGRESS_ROUNDS,
};
use ubi2_network::wire::{Blocks, GetBlocks, Hello, WireBlock};
use ubi2_network::{NetEvent, NetworkHandle};
use ubi2_rpc::{Chain, PeerStatus};

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
    /// The Stage-A designated proposer's address — every follower validates a block's author against it.
    designated_proposer: Option<AlloyAddr>,
    /// True iff THIS node is the designated proposer (it produces blocks; others do not).
    is_proposer: bool,
    /// Highest tip we have already requested a sync up to, so we don't spam overlapping range pulls.
    sync_in_flight_to: u64,
}

impl NetDriver {
    pub fn new(
        chain: Chain,
        handle: NetworkHandle,
        validator_key: Option<ubi2_network::ValidatorKey>,
        designated_proposer: Option<AlloyAddr>,
        is_proposer: bool,
    ) -> Self {
        chain.set_proposer_role(is_proposer, designated_proposer);
        NetDriver {
            chain,
            handle,
            peers: HashMap::new(),
            validator_key,
            designated_proposer,
            is_proposer,
            sync_in_flight_to: 0,
        }
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
                self.peers.entry(peer).or_default().multiaddr = Some(addr);
                tracing::info!(%peer, "peer connected");
                self.publish_peers();
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
        let bound = hello.verify_binding(&peer.to_bytes());
        // SEC-M5A-1: a `Hello.tip` is peer-advertised and UNAUTHENTICATED — a hostile peer can claim any
        // height. We record it for `ubi_getPeers`, but we only chase it if it is plausibly ahead (within
        // SYNC_MAX_LOOKAHEAD of our head). An implausibly-far tip (e.g. u64::MAX) is logged and ignored
        // for sync; it is never pinned as a target. A genuinely far-behind node still catches up because
        // each applied batch re-bounds the next acceptable look-ahead.
        let entry = self.peers.entry(peer).or_default();
        entry.validator = bound;
        entry.tip = Some(hello.tip);
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

    /// §5.1 block validation (fail-closed). A follower re-executes + matches the `state_root`; the
    /// proposer ignores its own echoed blocks (it produced them). On accept, relay + advance the
    /// advertised tip; on reject, penalize the peer.
    fn on_block(&mut self, from: PeerId, block: WireBlock) {
        let (local_h, _) = self.chain.tip();
        if block.number <= local_h {
            return; // already have this height (or behind via sync) — nothing to apply
        }
        if block.number > local_h + 1 {
            // A gap: we're missing parents. Before trusting this announcement's NUMBER (and pinning it as
            // a sync target) we fail closed on two SEC-M5A-1 conditions:
            //   1. The block must be AUTHENTICATED by the Stage-A designated proposer. `shallow_verify`
            //      already requires a valid proposer signature (it no longer passes an empty sig), and we
            //      additionally check the recovered/declared proposer IS our designated proposer. A
            //      forged UNSIGNED block claiming `number = u64::MAX` therefore never reaches `maybe_sync`.
            //   2. The advertised height must be within SYNC_MAX_LOOKAHEAD of our head (handled in
            //      `maybe_sync`) so even a *signed* (but absurd) number cannot pin an unreachable target.
            if !self.announced_tip_is_trustworthy(&block) {
                tracing::warn!(
                    %from, number = block.number,
                    "ignoring untrusted ahead-block announcement (unsigned / wrong proposer); not pinning tip"
                );
                self.handle.penalize_peer(from);
                return;
            }
            self.peers.entry(from).or_default().tip = Some((block.number, block.hash()));
            self.maybe_sync(from, block.number);
            return;
        }
        let block_id = (block.number, block.hash());
        match self.apply_wire_block(&block) {
            Ok(()) => {
                tracing::info!(
                    number = block.number,
                    txs = block.txs.len(),
                    "applied gossiped block"
                );
                // Record the source peer's tip (it produced/relayed this block) for `ubi_getPeers`.
                self.peers.entry(from).or_default().tip = Some(block_id);
                // Relay the valid block onward (gossipsub dedups by block hash) and re-advertise our tip.
                self.handle.publish_block(block);
                self.refresh_advertised_state();
            }
            Err(e) => {
                tracing::warn!(%from, number = block.number, error = %e, "rejecting block; penalizing peer");
                self.handle.penalize_peer(from);
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
        match self.designated_proposer {
            // In a networked Stage-A deployment the designated proposer is always set; only its signed
            // blocks advance the tip.
            Some(dp) => block.proposer == dp,
            // No designated proposer configured (single-node devnet) — there is no gossip peer to forge a
            // tip, but fail closed anyway: do not chase an ahead announcement we cannot attribute.
            None => false,
        }
    }

    /// Validate + apply one wire block against the local head (the shared follower path used by both live
    /// gossip and sync). Caches the block's raw txs so this node can later re-serve them on sync.
    fn apply_wire_block(&self, block: &WireBlock) -> Result<(), String> {
        self.chain
            .validate_and_apply_block(
                block.number,
                block.parent_hash,
                block.timestamp,
                block.txs_root,
                block.state_root,
                block.proposer,
                &block.proposer_sig,
                &block.txs,
                self.designated_proposer,
            )
            .map_err(|e| e.to_string())?;
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

    /// §4.2 sync client: apply a received batch in ascending order; abandon the peer on the first invalid
    /// block (it is on a bad/forked chain — AC-F8). After catching up, live gossip continues.
    fn on_sync_response(&mut self, from: PeerId, resp: Blocks) {
        let mut applied = 0usize;
        for block in &resp.blocks {
            let (head, _) = self.chain.tip();
            if block.number <= head {
                continue; // already have it (overlapping batch)
            }
            if block.number != head + 1 {
                break; // out of order / gap — stop and re-request from the new head
            }
            if !block.shallow_verify() {
                tracing::warn!(%from, number = block.number, "sync block failed shallow-verify; abandoning peer");
                self.handle.penalize_peer(from);
                break;
            }
            match self.apply_wire_block(block) {
                Ok(()) => applied += 1,
                Err(e) => {
                    tracing::warn!(%from, number = block.number, error = %e, "sync block rejected; abandoning peer");
                    self.handle.penalize_peer(from);
                    break;
                }
            }
        }
        // Allow a follow-up request regardless of the branch below (the in-flight pull has resolved).
        self.sync_in_flight_to = 0;

        if applied > 0 {
            tracing::info!(%from, applied, tip = self.chain.tip().0, "applied sync batch");
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

        // SEC-M5A-1: NO forward progress (empty batch, an OutboundFailure-synthesized empty response, an
        // overlapping batch, or a peer serving blocks it cannot link). Re-issuing `maybe_sync` here
        // unconditionally — as the old code did — produces an UNBOUNDED re-request loop against a peer
        // advertising a tip (possibly forged via u64::MAX) it cannot serve. Instead we count no-progress
        // rounds and, past the bound, PENALIZE + abandon the peer rather than loop. The peer must offer a
        // genuinely-progressing response (or re-advertise) to be chased again.
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
            // Penalize (counts toward the greylist threshold) and stop chasing this peer's tip: drop our
            // recorded tip for it so a later `maybe_sync` does not re-target the same unreachable height.
            self.handle.penalize_peer(from);
            if let Some(e) = self.peers.get_mut(&from) {
                e.tip = None;
            }
            return;
        }
        // Bounded retry: one more attempt toward the (still-recorded, still-plausible) tip.
        tracing::debug!(%from, rounds, "sync made no progress; bounded retry");
        if let Some(peer_tip) = self.peers.get(&from).and_then(|e| e.tip).map(|(h, _)| h) {
            self.maybe_sync(from, peer_tip);
        }
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
            txs_root: b.txs_root,
            state_root: b.state_root,
            proposer: b.proposer,
            proposer_sig: b.proposer_sig.clone(),
            txs: self.chain.raw_txs_for_block(b),
        }
    }

    /// The PROPOSER's per-tick action: produce a block from the local mempool and broadcast it. Returns
    /// the produced block so the caller can persist + log. Followers never call this (Stage A).
    pub fn tick_proposer(&mut self, timestamp: u64) -> Option<ubi2_rpc::Block> {
        if !self.is_proposer {
            return None;
        }
        let block = self.chain.produce_block(timestamp);
        let wire = self.wire_block_from(&block);
        self.handle.publish_block(wire);
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
        let driver = NetDriver::new(chain, handle, None, designated, false);
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
