//! `ubi2-network` — the M5 Stage-A P2P layer (libp2p), fully isolated from the deterministic core.
//!
//! ALL libp2p/async networking lives here (ADR-0004 Decision 1); `crates/runtime` never depends on this
//! crate, and this crate never depends on `crates/runtime`'s state model — it **moves bytes and verifies
//! the hashes/signatures it can**, deferring full validation to `crates/node`.
//!
//! ## What this crate does
//! - **Transport:** TCP + Noise + Yamux (libp2p `SwarmBuilder`), peer identity = an Ed25519 keypair.
//! - **Gossip:** gossipsub on `ubi2/tx/1` (pending txs) and `ubi2/block/1` (new blocks); the
//!   **message-id = the tx hash / block hash** (`keccak256(payload)`), giving free, correct dedup (§3.1).
//! - **Sync:** request-response `ubi2/sync/1` for block-range pulls, bounded by `SYNC_MAX_BATCH` (§4.2).
//! - **Discovery:** static bootstrap dial + optional mDNS; **explicit dial works WITHOUT mDNS** so tests
//!   are deterministic (§1).
//! - **Anti-abuse:** a per-peer token-bucket rate limiter + invalid-message greylisting (FU-1, §3.3),
//!   on top of gossipsub's own peer scoring.
//!
//! ## The node-driving API (the seam to `crates/node`)
//! The node owns the chain; this crate owns the network. They talk over two channels:
//! - The node sends [`NetCmd`]s into the swarm via [`NetworkHandle`] (`publish_tx`, `publish_block`,
//!   `request_blocks`, `dial`, …).
//! - The swarm emits [`NetEvent`]s on the handle's event stream (`PeerConnected`, `TxReceived`,
//!   `BlockReceived`, `SyncRequest`, `SyncResponse`, …).
//!
//! The node decides validity (re-execute, state-root match, mempool admission); this crate decides only
//! transport-level things (rate limits, malformed-drop, the message-id dedup gossipsub gives us).

pub mod behaviour;
pub mod codec;
pub mod config;
pub mod consts;
pub mod ratelimit;
pub mod wire;

use std::collections::HashMap;
use std::time::{Duration, Instant};

use futures::StreamExt;
use libp2p::multiaddr::Protocol;
use libp2p::request_response::{self, OutboundRequestId, ResponseChannel};
use libp2p::swarm::dial_opts::{DialOpts, PeerCondition};
use libp2p::swarm::SwarmEvent;
use libp2p::{gossipsub, mdns, Multiaddr, PeerId, Swarm};
use tokio::sync::mpsc;

use crate::behaviour::{block_topic, tx_topic, Ubi2Behaviour, Ubi2BehaviourEvent};
use crate::config::NetworkConfig;
use crate::ratelimit::RateLimiter;
use crate::wire::{Blocks, GetBlocks, Hash, Hello, SyncRequest, SyncResponse, WireBlock};

pub use config::ValidatorKey;

/// A connected peer, as the node sees it (the `ubi_getPeers` shape lives in `crates/rpc`; this is the
/// transport-level record the node maps from).
#[derive(Clone, Debug)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    /// The address we connected over.
    pub multiaddr: Multiaddr,
    /// The bound validator address, if the peer proved a PeerId↔address binding at the handshake (§4.1).
    pub validator: Option<alloy_primitives::Address>,
    /// The peer's last-reported tip `(height, hash)` from its `Hello`.
    pub tip: Option<(u64, Hash)>,
}

/// Events the swarm emits to the node. The node validates/acts; the network only reports.
#[derive(Debug)]
pub enum NetEvent {
    /// The swarm is listening on this address (report it so a bootstrap node can publish its multiaddr).
    Listening { addr: Multiaddr },
    /// A peer connected (transport-level). The handshake `Hello` arrives separately as [`NetEvent::Hello`].
    PeerConnected { peer: PeerId, addr: Multiaddr },
    /// A peer disconnected.
    PeerDisconnected { peer: PeerId },
    /// A peer's `Hello` handshake (§4.1). The node checks `genesis_hash`/`chain_id` and the binding; on a
    /// network mismatch it asks the handle to disconnect the peer.
    Hello { peer: PeerId, hello: Box<Hello> },
    /// A gossiped tx (raw RLP) passed transport-level rate-limiting + dedup. The node validates it via
    /// `ingest_raw_tx` and, if valid, admits + re-broadcasts (§3.2).
    TxReceived {
        from: PeerId,
        /// The gossipsub message-id (= the tx hash) — the node uses it for its own dedup/logging.
        id: Hash,
        raw: Vec<u8>,
    },
    /// A gossiped block. The node runs `validate_and_apply_block` (re-execute → state-root match, §5.1).
    BlockReceived {
        from: PeerId,
        id: Hash,
        block: Box<WireBlock>,
    },
    /// An inbound sync request: a peer asked for `[from, to]`. The node fulfils it via
    /// [`NetworkHandle::respond_blocks`] with the matching token.
    SyncRequest {
        from: PeerId,
        request: GetBlocks,
        /// Opaque token the node passes back to [`NetworkHandle::respond_blocks`].
        token: SyncResponder,
    },
    /// A sync response to one of our [`NetworkHandle::request_blocks`] calls arrived.
    SyncResponse {
        from: PeerId,
        request_id: u64,
        blocks: Box<Blocks>,
    },
    /// A peer crossed the invalid-message greylist threshold and was disconnected (FU-1, §3.3).
    PeerGreylisted { peer: PeerId },
}

/// An opaque handle the node returns blocks through, fulfilling a [`NetEvent::SyncRequest`]. It carries
/// the request-response [`ResponseChannel`] so the node never sees libp2p internals.
#[derive(Debug)]
pub struct SyncResponder {
    channel: ResponseChannel<SyncResponse>,
}

/// Commands the node sends into the swarm.
enum NetCmd {
    Dial(Multiaddr),
    PublishTx(Vec<u8>),
    PublishBlock(WireBlock),
    RequestBlocks {
        peer: PeerId,
        request: GetBlocks,
        /// Echoed back in the [`NetEvent::SyncResponse`] so the node can correlate.
        reply_id: u64,
    },
    RespondBlocks {
        responder: SyncResponder,
        blocks: Blocks,
    },
    /// Tell the swarm the node rejected a peer's last message as invalid (penalize → maybe greylist).
    PenalizePeer(PeerId),
    /// Disconnect a peer (network mismatch / wrong-network handshake, §4.1).
    Disconnect(PeerId),
    /// Update the local `Hello` we send on new connections (e.g. after the tip advances).
    UpdateHello(Hello),
}

/// The handle the node drives the network with. Clone-cheap (it is just the command sender + metadata).
#[derive(Clone)]
pub struct NetworkHandle {
    cmd_tx: mpsc::UnboundedSender<NetCmd>,
    local_peer_id: PeerId,
    request_seq: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl NetworkHandle {
    /// This node's libp2p `PeerId` (the transport identity).
    pub fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Dial a peer by multiaddr (explicit bootstrap; works without mDNS — deterministic, §1).
    pub fn dial(&self, addr: Multiaddr) {
        let _ = self.cmd_tx.send(NetCmd::Dial(addr));
    }

    /// Publish a raw tx on `ubi2/tx/1`. Idempotent on the network (gossipsub dedups by message-id =
    /// the tx hash); call it both for locally-submitted txs and for valid gossiped txs being relayed.
    pub fn publish_tx(&self, raw: Vec<u8>) {
        let _ = self.cmd_tx.send(NetCmd::PublishTx(raw));
    }

    /// Publish a block on `ubi2/block/1` (the proposer broadcasts; followers re-broadcast valid blocks).
    pub fn publish_block(&self, block: WireBlock) {
        let _ = self.cmd_tx.send(NetCmd::PublishBlock(block));
    }

    /// Request a block range from a specific peer (sync). Returns a correlation id echoed in the
    /// resulting [`NetEvent::SyncResponse`]. The request range is clamped server-side to `SYNC_MAX_BATCH`.
    pub fn request_blocks(&self, peer: PeerId, request: GetBlocks) -> u64 {
        let reply_id = self
            .request_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let _ = self.cmd_tx.send(NetCmd::RequestBlocks {
            peer,
            request,
            reply_id,
        });
        reply_id
    }

    /// Fulfil an inbound [`NetEvent::SyncRequest`] with the requested blocks.
    pub fn respond_blocks(&self, responder: SyncResponder, blocks: Blocks) {
        let _ = self
            .cmd_tx
            .send(NetCmd::RespondBlocks { responder, blocks });
    }

    /// Tell the network the node validated a peer's last message and rejected it as invalid (§3.2/§3.3).
    /// The limiter increments the peer's invalid count and greylists it past the threshold.
    pub fn penalize_peer(&self, peer: PeerId) {
        let _ = self.cmd_tx.send(NetCmd::PenalizePeer(peer));
    }

    /// Disconnect a peer (e.g. a wrong-network `Hello`, §4.1 / AC-F7).
    pub fn disconnect(&self, peer: PeerId) {
        let _ = self.cmd_tx.send(NetCmd::Disconnect(peer));
    }

    /// Update the `Hello` this node advertises (after the tip advances, the new tip is gossiped to peers
    /// on the next connection; existing peers learn the new tip from block gossip).
    pub fn update_hello(&self, hello: Hello) {
        let _ = self.cmd_tx.send(NetCmd::UpdateHello(hello));
    }
}

/// Start the network: build the swarm, spawn its event loop on the current tokio runtime, and return a
/// [`NetworkHandle`] plus the inbound [`NetEvent`] stream. The caller (the node) must keep polling the
/// receiver; if it is dropped, the loop shuts down.
pub fn start(
    config: NetworkConfig,
) -> Result<(NetworkHandle, mpsc::UnboundedReceiver<NetEvent>), String> {
    let local_peer_id = PeerId::from(config.keypair.public());

    let mut swarm = build_swarm(&config)?;

    // Listen.
    for addr in &config.listen_addrs {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| format!("listen_on {addr}: {e}"))?;
    }
    // Parse the static bootstrap peers into reconnect targets. We do NOT issue a one-shot startup dial
    // here: a single dial at swarm start races a peer that has not begun listening yet and fails
    // PERMANENTLY (the classic flaky-mesh bug). Instead the reconnect sweep (run on a fast timer, first
    // tick immediately) re-dials any not-yet-connected bootstrap peer until the full mesh forms — so
    // connectivity is independent of node boot order and survives transient dial failures (§1).
    let mut bootstrap = Vec::new();
    for addr in &config.bootstrap_peers {
        match split_bootstrap(addr) {
            Some((peer_id, dial_addr)) => bootstrap.push(BootstrapPeer::new(peer_id, dial_addr)),
            None => {
                // No `/p2p/<id>` suffix ⇒ we cannot track connectivity by PeerId. Fall back to a plain
                // one-shot dial (best-effort); the devnet/test always supplies the suffix.
                tracing::warn!(%addr, "bootstrap multiaddr has no /p2p/<id> suffix; one-shot dial only (no reconnect)");
                if let Err(e) = swarm.dial(addr.clone()) {
                    tracing::warn!(%addr, error = %e, "bootstrap dial failed");
                }
            }
        }
    }
    // Subscribe to both gossip topics.
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&tx_topic())
        .map_err(|e| format!("subscribe tx topic: {e}"))?;
    swarm
        .behaviour_mut()
        .gossipsub
        .subscribe(&block_topic())
        .map_err(|e| format!("subscribe block topic: {e}"))?;

    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<NetCmd>();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel::<NetEvent>();

    let handle = NetworkHandle {
        cmd_tx,
        local_peer_id,
        request_seq: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
    };

    let loop_state = LoopState {
        swarm,
        cmd_rx,
        evt_tx,
        rate: RateLimiter::new(),
        pending_requests: HashMap::new(),
        local_hello: build_initial_hello(&config),
        bootstrap,
        config,
        local_peer_id,
    };
    tokio::spawn(run_loop(loop_state));

    Ok((handle, evt_rx))
}

/// Build the libp2p swarm: TCP + Noise + Yamux, the fused behaviour, a generous idle timeout.
fn build_swarm(config: &NetworkConfig) -> Result<Swarm<Ubi2Behaviour>, String> {
    let heartbeat = config.gossip_heartbeat;
    let enable_mdns = config.enable_mdns;
    let swarm = libp2p::SwarmBuilder::with_existing_identity(config.keypair.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| format!("tcp transport: {e}"))?
        .with_behaviour(|key| {
            Ubi2Behaviour::new(key, PeerId::from(key.public()), heartbeat, enable_mdns)
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
        })
        .map_err(|e| format!("behaviour: {e}"))?
        .with_swarm_config(|c| c.with_idle_connection_timeout(std::time::Duration::from_secs(60)))
        .build();
    Ok(swarm)
}

/// Build the `Hello` this node advertises at genesis (tip = `(0, genesis_hash)` until the node updates it
/// via [`NetworkHandle::update_hello`]). The node, which owns the chain + key, will normally call
/// `update_hello` with the real tip and validator binding immediately after `start`.
fn build_initial_hello(config: &NetworkConfig) -> Hello {
    let local_peer_id = PeerId::from(config.keypair.public());
    let (validator, peer_proof) = match &config.validator_key {
        Some(vk) => {
            let digest = Hello::proof_digest(&local_peer_id.to_bytes(), &config.genesis_hash);
            (Some(vk.address()), vk.sign_digest(&digest))
        }
        None => (None, Vec::new()),
    };
    Hello {
        genesis_hash: config.genesis_hash,
        chain_id: config.chain_id,
        tip: (0, config.genesis_hash),
        validator,
        peer_proof,
        protocol_ver: consts::PROTOCOL_VERSION,
    }
}

/// What an outstanding outbound sync request is waiting for (so the response is routed correctly).
enum PendingKind {
    /// A handshake: the response is the peer's `Hello`.
    Hello,
    /// A block-range pull: the response is `Blocks`; carry the node's correlation `reply_id`.
    Blocks(u64),
}

/// A single static bootstrap target the swarm keeps a live connection to (§1 connectivity maintenance).
///
/// The mesh's connectivity comes from RE-DIAL-UNTIL-CONNECTED, not from any fixed sleep: every reconnect
/// tick, for each target whose `PeerId` is not currently connected (the swarm is the source of truth),
/// the swarm re-issues a dial — bounded by a per-target exponential backoff so a genuinely-down peer is
/// not hammered, but with **no give-up state**, so a cold-start ordering race (a peer that had not begun
/// listening when we first dialed) or a transient drop always converges to the full mesh.
struct BootstrapPeer {
    /// The peer's libp2p `PeerId`, parsed from the `/p2p/<id>` suffix of its bootstrap multiaddr. We dial
    /// by `PeerId` + address so libp2p's own `PeerCondition::DisconnectedAndNotDialing` dedups concurrent
    /// dials (handling the simultaneous-open / already-dialing race for us).
    peer_id: PeerId,
    /// The dialable address (the bootstrap multiaddr with the `/p2p/...` suffix stripped — libp2p wants
    /// the transport address plus the `PeerId` supplied separately via `DialOpts`).
    addr: Multiaddr,
    /// Earliest instant at which we may re-dial this peer (the current backoff deadline). `None` ⇒ dial
    /// on the next tick (initial state / just reset after a successful connect).
    next_dial_at: Option<Instant>,
    /// Current backoff window; grows on each failed/abandoned dial (capped), resets on a successful
    /// connect.
    backoff: Duration,
}

impl BootstrapPeer {
    fn new(peer_id: PeerId, addr: Multiaddr) -> Self {
        BootstrapPeer {
            peer_id,
            addr,
            next_dial_at: None,
            backoff: Duration::from_millis(consts::RECONNECT_BACKOFF_MIN_MS),
        }
    }

    /// After issuing (or skipping) a dial, schedule the next attempt and grow the backoff toward the cap.
    fn arm_backoff(&mut self, now: Instant) {
        self.next_dial_at = Some(now + self.backoff);
        let next = self.backoff.saturating_mul(2);
        let cap = Duration::from_millis(consts::RECONNECT_BACKOFF_MAX_MS);
        self.backoff = next.min(cap);
    }

    /// On a successful connection to this peer, reset the backoff so a later drop re-dials immediately.
    fn on_connected(&mut self) {
        self.backoff = Duration::from_millis(consts::RECONNECT_BACKOFF_MIN_MS);
        self.next_dial_at = None;
    }
}

/// Split a bootstrap multiaddr into `(PeerId, dial_addr)` when it carries a `/p2p/<id>` suffix. The
/// suffix is REQUIRED for robust reconnect: knowing the target `PeerId` lets us ask the swarm
/// "is this peer connected?" and dedup concurrent dials. A suffix-less multiaddr cannot be tracked this
/// way; it falls back to a plain one-shot dial (logged), but the devnet/test always supplies `/p2p/...`.
fn split_bootstrap(addr: &Multiaddr) -> Option<(PeerId, Multiaddr)> {
    let mut peer_id = None;
    let mut dial_addr = Multiaddr::empty();
    for proto in addr.iter() {
        if let Protocol::P2p(id) = proto {
            peer_id = Some(id);
        } else {
            dial_addr.push(proto);
        }
    }
    peer_id.map(|id| (id, dial_addr))
}

/// The swarm event-loop state.
struct LoopState {
    swarm: Swarm<Ubi2Behaviour>,
    cmd_rx: mpsc::UnboundedReceiver<NetCmd>,
    evt_tx: mpsc::UnboundedSender<NetEvent>,
    rate: RateLimiter,
    /// Map libp2p `OutboundRequestId` → what its response is (a handshake `Hello` or a `Blocks` pull).
    pending_requests: HashMap<OutboundRequestId, PendingKind>,
    /// The `Hello` this node advertises: sent as a handshake when WE dial a peer, and echoed back when a
    /// peer handshakes US (spec §4.1 "on a new connection, peers exchange a Hello").
    local_hello: Hello,
    /// The static bootstrap peers we keep a live connection to (the reconnect-until-connected set, §1).
    /// Keyed-by-`PeerId` view lives in `bootstrap`; lookups on connect/disconnect are linear (N≤handful).
    bootstrap: Vec<BootstrapPeer>,
    #[allow(dead_code)]
    config: NetworkConfig,
    #[allow(dead_code)]
    local_peer_id: PeerId,
}

impl LoopState {
    /// The reconnect sweep (§1): for every bootstrap peer NOT currently connected, re-dial it (subject to
    /// its backoff). The swarm's own connection table is the source of truth, so a peer reached via an
    /// INBOUND connection is correctly seen as connected and not re-dialed; a peer we never managed to
    /// reach (boot-order race) or one that dropped is dialed again, indefinitely, until the mesh is whole.
    ///
    /// `PeerCondition::DisconnectedAndNotDialing` makes each dial a no-op when a connection or an in-flight
    /// dial already exists, so this never piles up concurrent dials or fights libp2p's simultaneous-open
    /// resolution — it just guarantees that a missing connection is always being retried.
    fn reconnect_sweep(&mut self) {
        let now = Instant::now();
        for bp in &mut self.bootstrap {
            if self.swarm.is_connected(&bp.peer_id) {
                bp.on_connected();
                continue;
            }
            if bp.next_dial_at.is_some_and(|at| now < at) {
                continue; // still inside this peer's backoff window
            }
            let opts = DialOpts::peer_id(bp.peer_id)
                .addresses(vec![bp.addr.clone()])
                .condition(PeerCondition::DisconnectedAndNotDialing)
                .build();
            match self.swarm.dial(opts) {
                Ok(()) => {
                    tracing::debug!(peer = %bp.peer_id, addr = %bp.addr, "reconnect: dialing bootstrap peer");
                    // A new dial was issued: arm the backoff so we don't re-dial while it is in flight.
                    bp.arm_backoff(now);
                }
                Err(e) => {
                    // `DialPeerConditionFalse` (already connected / already dialing) is the common, benign
                    // case — exactly what the condition is for. Do NOT grow the backoff here: the dial is
                    // already in-flight and growing the backoff on a non-event would delay the retry when
                    // that in-flight dial eventually fails (the OutgoingConnectionError path). Anything that
                    // is not a condition-gate (genuinely unexpected) is logged at debug.
                    tracing::trace!(peer = %bp.peer_id, error = %e, "reconnect: dial skipped (condition not met)");
                }
            }
        }
    }

    /// Note a successful connection so the matching bootstrap target resets its backoff (a later drop then
    /// re-dials promptly). Also pin the peer as a gossipsub explicit peer so it stays in the mesh under
    /// churn — keeping tx/block gossip flowing once connectivity is up.
    fn note_connected(&mut self, peer: &PeerId) {
        for bp in &mut self.bootstrap {
            if &bp.peer_id == peer {
                bp.on_connected();
            }
        }
        self.swarm.behaviour_mut().gossipsub.add_explicit_peer(peer);
    }
}

async fn run_loop(mut st: LoopState) {
    // The reconnect sweep timer (§1): keeps re-dialing any not-yet-connected bootstrap peer until the
    // full mesh forms and stays formed. The FIRST tick fires immediately (this is what replaces the
    // old one-shot startup dial), so a node begins dialing its bootstrap set the instant it is up.
    let mut reconnect = tokio::time::interval(Duration::from_millis(consts::RECONNECT_TICK_MS));
    reconnect.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            cmd = st.cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => handle_cmd(&mut st, cmd),
                    None => break, // handle dropped → shut down
                }
            }
            event = st.swarm.select_next_some() => {
                handle_swarm_event(&mut st, event);
            }
            _ = reconnect.tick() => {
                st.reconnect_sweep();
            }
        }
    }
}

fn handle_cmd(st: &mut LoopState, cmd: NetCmd) {
    match cmd {
        NetCmd::Dial(addr) => {
            if let Err(e) = st.swarm.dial(addr.clone()) {
                tracing::warn!(%addr, error = %e, "dial failed");
            }
        }
        NetCmd::PublishTx(raw) => {
            if let Err(e) = st.swarm.behaviour_mut().gossipsub.publish(tx_topic(), raw) {
                // `InsufficientPeers` is normal before the mesh forms; log at debug.
                tracing::debug!(error = %e, "publish_tx");
            }
        }
        NetCmd::PublishBlock(block) => {
            let bytes = block.encode();
            if let Err(e) = st
                .swarm
                .behaviour_mut()
                .gossipsub
                .publish(block_topic(), bytes)
            {
                tracing::debug!(error = %e, "publish_block");
            }
        }
        NetCmd::RequestBlocks {
            peer,
            request,
            reply_id,
        } => {
            let rid = st
                .swarm
                .behaviour_mut()
                .sync
                .send_request(&peer, SyncRequest::GetBlocks(request));
            st.pending_requests
                .insert(rid, PendingKind::Blocks(reply_id));
        }
        NetCmd::RespondBlocks { responder, blocks } => {
            if st
                .swarm
                .behaviour_mut()
                .sync
                .send_response(responder.channel, SyncResponse::Blocks(blocks))
                .is_err()
            {
                tracing::debug!("sync response channel closed before send");
            }
        }
        NetCmd::PenalizePeer(peer) => {
            if st.rate.penalize(&peer, Instant::now()) {
                let _ = st.swarm.disconnect_peer_id(peer);
                let _ = st.evt_tx.send(NetEvent::PeerGreylisted { peer });
            }
        }
        NetCmd::Disconnect(peer) => {
            let _ = st.swarm.disconnect_peer_id(peer);
        }
        NetCmd::UpdateHello(hello) => {
            st.local_hello = hello;
        }
    }
}

fn handle_swarm_event(st: &mut LoopState, event: SwarmEvent<Ubi2BehaviourEvent>) {
    match event {
        SwarmEvent::NewListenAddr { address, .. } => {
            let _ = st.evt_tx.send(NetEvent::Listening {
                addr: address.clone(),
            });
        }
        SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            // Reset this peer's reconnect backoff + pin it as a gossipsub explicit peer (mesh health).
            st.note_connected(&peer_id);
            let addr = endpoint.get_remote_address().clone();
            let _ = st.evt_tx.send(NetEvent::PeerConnected {
                peer: peer_id,
                addr,
            });
            // The DIALER initiates the handshake (§4.1): send our `Hello` over the sync protocol. The
            // listener responds with its own `Hello` (handled below). We only initiate on the outbound
            // side so the handshake happens exactly once per connection.
            if endpoint.is_dialer() {
                let rid = st
                    .swarm
                    .behaviour_mut()
                    .sync
                    .send_request(&peer_id, SyncRequest::Hello(st.local_hello.clone()));
                st.pending_requests.insert(rid, PendingKind::Hello);
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            num_established,
            ..
        } => {
            st.rate.forget(&peer_id);
            // Only surface a disconnect (and trigger a re-dial) when the LAST connection to this peer is
            // gone — a connection-churn event that still leaves a live connection must not look like a
            // disconnect to the node. The reconnect sweep re-dials a now-disconnected bootstrap peer on
            // its next tick, so a dropped mesh edge self-heals.
            if num_established == 0 {
                let _ = st.evt_tx.send(NetEvent::PeerDisconnected { peer: peer_id });
            }
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            // A dial race (peer not yet listening / ECONNREFUSED / simultaneous-open) is EXPECTED during
            // cold start. We never give up: reset this peer's backoff deadline so the reconnect sweep
            // re-dials on its very next tick. Clearing `next_dial_at` (and resetting backoff to the
            // minimum floor) ensures the sweep doesn't sit behind an exponentially-grown window waiting
            // to retry a peer that simply wasn't up yet when we dialed.
            tracing::debug!(?peer_id, error = %error, "outgoing connection error; resetting backoff for immediate retry");
            if let Some(pid) = peer_id {
                for bp in &mut st.bootstrap {
                    if bp.peer_id == pid {
                        bp.next_dial_at = None;
                        bp.backoff = Duration::from_millis(consts::RECONNECT_BACKOFF_MIN_MS);
                        break;
                    }
                }
            }
        }
        SwarmEvent::Behaviour(ev) => handle_behaviour_event(st, ev),
        _ => {}
    }
}

fn handle_behaviour_event(st: &mut LoopState, ev: Ubi2BehaviourEvent) {
    match ev {
        Ubi2BehaviourEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id,
            message,
        }) => {
            // Transport-level rate limit (FU-1): drop (do not surface/forward) over-rate messages.
            if !st.rate.allow(&propagation_source, Instant::now()) {
                tracing::debug!(peer = %propagation_source, "rate-limited gossip dropped");
                return;
            }
            let id = msg_id_to_hash(&message_id);
            let topic = message.topic.as_str().to_string();
            if topic == consts::TOPIC_TX {
                // Bounds-check the raw tx; malformed → drop + penalize the source (do not forward).
                match wire::TxAnnounce::decode(&message.data) {
                    Ok(tx) => {
                        let _ = st.evt_tx.send(NetEvent::TxReceived {
                            from: propagation_source,
                            id,
                            raw: tx.raw,
                        });
                    }
                    Err(_) => {
                        penalize(st, propagation_source);
                    }
                }
            } else if topic == consts::TOPIC_BLOCK {
                match WireBlock::decode(&message.data) {
                    Ok(block) if block.shallow_verify() => {
                        let _ = st.evt_tx.send(NetEvent::BlockReceived {
                            from: propagation_source,
                            id,
                            block: Box::new(block),
                        });
                    }
                    // Malformed or a block whose txs_root/sig doesn't check out → drop + penalize.
                    _ => penalize(st, propagation_source),
                }
            }
        }
        Ubi2BehaviourEvent::Gossipsub(_) => {}
        Ubi2BehaviourEvent::Sync(request_response::Event::Message { peer, message, .. }) => {
            match message {
                request_response::Message::Request {
                    request, channel, ..
                } => match request {
                    // A peer handshakes us: surface its Hello to the node AND reply with our Hello
                    // (§4.1, "peers exchange a Hello").
                    SyncRequest::Hello(hello) => {
                        let _ = st.evt_tx.send(NetEvent::Hello {
                            peer,
                            hello: Box::new(hello),
                        });
                        let _ = st
                            .swarm
                            .behaviour_mut()
                            .sync
                            .send_response(channel, SyncResponse::Hello(st.local_hello.clone()));
                    }
                    // A peer asks for a block range: hand the node a responder token (§4.2).
                    SyncRequest::GetBlocks(request) => {
                        let _ = st.evt_tx.send(NetEvent::SyncRequest {
                            from: peer,
                            request,
                            token: SyncResponder { channel },
                        });
                    }
                },
                request_response::Message::Response {
                    request_id,
                    response,
                } => match (st.pending_requests.remove(&request_id), response) {
                    // The handshake reply: surface the peer's Hello.
                    (Some(PendingKind::Hello), SyncResponse::Hello(hello)) => {
                        let _ = st.evt_tx.send(NetEvent::Hello {
                            peer,
                            hello: Box::new(hello),
                        });
                    }
                    // A block-range pull reply: surface the blocks correlated to the node's reply_id.
                    (Some(PendingKind::Blocks(reply_id)), SyncResponse::Blocks(blocks)) => {
                        let _ = st.evt_tx.send(NetEvent::SyncResponse {
                            from: peer,
                            request_id: reply_id,
                            blocks: Box::new(blocks),
                        });
                    }
                    // A mismatched/late response — drop.
                    _ => {}
                },
            }
        }
        Ubi2BehaviourEvent::Sync(request_response::Event::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        }) => {
            // If the failed request was a blocks pull, emit an empty SyncResponse so the node driver
            // resets `sync_in_flight_to = 0` and re-queues the range pull. Without this, the
            // `sync_in_flight_to` gate stays set and the node never re-requests the missing range —
            // causing a follower that had a transient sync failure to stall indefinitely at the height
            // it was at when the pull was issued (EC-4 liveness bug).
            if let Some(PendingKind::Blocks(reply_id)) = st.pending_requests.remove(&request_id) {
                tracing::debug!(%peer, ?error, "sync outbound failure; unblocking sync gate with empty response");
                let _ = st.evt_tx.send(NetEvent::SyncResponse {
                    from: peer,
                    request_id: reply_id,
                    blocks: Box::new(wire::Blocks { blocks: vec![] }),
                });
            } else {
                tracing::debug!(%peer, ?error, "sync outbound failure (hello/other)");
            }
        }
        Ubi2BehaviourEvent::Sync(_) => {}
        Ubi2BehaviourEvent::Mdns(mdns::Event::Discovered(list)) => {
            // mDNS-discovered peers are dialed (devnet convenience). Tests run with mDNS off.
            for (peer, addr) in list {
                tracing::debug!(%peer, %addr, "mdns discovered; dialing");
                let _ = st.swarm.dial(addr);
            }
        }
        Ubi2BehaviourEvent::Mdns(mdns::Event::Expired(_)) => {}
    }
}

/// Penalize a peer that sent an invalid/malformed gossip message; greylist past the threshold (§3.3).
fn penalize(st: &mut LoopState, peer: PeerId) {
    if st.rate.penalize(&peer, Instant::now()) {
        let _ = st.swarm.disconnect_peer_id(peer);
        let _ = st.evt_tx.send(NetEvent::PeerGreylisted { peer });
    }
}

fn msg_id_to_hash(id: &gossipsub::MessageId) -> Hash {
    let mut out = [0u8; 32];
    let bytes = &id.0;
    let n = bytes.len().min(32);
    out[..n].copy_from_slice(&bytes[..n]);
    Hash::from(out)
}

#[cfg(test)]
mod reconnect_tests {
    use super::*;
    use libp2p::identity::Keypair;

    fn sample_peer_id() -> PeerId {
        PeerId::from(Keypair::generate_ed25519().public())
    }

    /// `split_bootstrap` extracts the `PeerId` from a `/p2p/<id>`-suffixed multiaddr and returns the
    /// transport address WITHOUT the suffix (what `DialOpts::addresses` expects) — the parse the
    /// reconnect-until-connected sweep relies on to track each bootstrap target by its PeerId.
    #[test]
    fn split_bootstrap_extracts_peer_id_and_strips_suffix() {
        let pid = sample_peer_id();
        let addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/19561/p2p/{pid}")
            .parse()
            .unwrap();
        let (got_id, dial_addr) = split_bootstrap(&addr).expect("has /p2p/ suffix");
        assert_eq!(got_id, pid, "PeerId recovered from the /p2p/<id> suffix");
        assert_eq!(
            dial_addr,
            "/ip4/127.0.0.1/tcp/19561".parse::<Multiaddr>().unwrap(),
            "dial address has the /p2p/<id> suffix stripped"
        );
    }

    /// A suffix-less multiaddr cannot be tracked by PeerId → `None` (the caller falls back to a one-shot
    /// dial). This is the boundary the devnet/test never hits (it always supplies `/p2p/...`).
    #[test]
    fn split_bootstrap_without_suffix_is_none() {
        let addr: Multiaddr = "/ip4/127.0.0.1/tcp/19561".parse().unwrap();
        assert!(split_bootstrap(&addr).is_none());
    }

    /// The per-peer backoff grows exponentially and is capped at `RECONNECT_BACKOFF_MAX_MS`, so a
    /// genuinely-down peer is retried forever (NO give-up state) but never hammered. A successful connect
    /// resets the backoff to the floor + clears the next-dial deadline (so a later drop re-dials at once).
    #[test]
    fn backoff_grows_to_cap_then_resets_on_connect() {
        let mut bp = BootstrapPeer::new(sample_peer_id(), "/ip4/127.0.0.1/tcp/1".parse().unwrap());
        assert_eq!(
            bp.backoff,
            Duration::from_millis(consts::RECONNECT_BACKOFF_MIN_MS)
        );
        assert!(bp.next_dial_at.is_none(), "initial state dials immediately");

        let now = Instant::now();
        let cap = Duration::from_millis(consts::RECONNECT_BACKOFF_MAX_MS);
        // Arm many times: the backoff must climb monotonically and saturate AT the cap, never beyond it.
        let mut prev = bp.backoff;
        for _ in 0..20 {
            bp.arm_backoff(now);
            assert!(bp.next_dial_at.is_some(), "a dial deadline is always set");
            assert!(bp.backoff <= cap, "backoff never exceeds the cap");
            assert!(bp.backoff >= prev, "backoff is monotonic up to the cap");
            prev = bp.backoff;
        }
        assert_eq!(bp.backoff, cap, "backoff saturates exactly at the cap");

        // A successful connect resets everything: ready to re-dial immediately if it later drops.
        bp.on_connected();
        assert_eq!(
            bp.backoff,
            Duration::from_millis(consts::RECONNECT_BACKOFF_MIN_MS)
        );
        assert!(bp.next_dial_at.is_none());
    }
}
