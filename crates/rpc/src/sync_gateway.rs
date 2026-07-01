//! WebSocket sync gateway (spec `07-browser-light-node.md` §3.1, ADR-0006 Decision 2).
//!
//! A browser cannot open a raw TCP socket or speak libp2p. This module adds a `/sync` WebSocket
//! endpoint to the node's existing HTTP server: the browser opens a `ws://…/sync` connection and
//! exchanges the **exact same `SyncRequest`/`SyncResponse` bytes** the M5 `ubi2/sync/1`
//! protocol defines, just framed in WebSocket messages instead of a libp2p request-response stream.
//!
//! ## What the gateway does
//! 1. On connection: wait for a `SyncRequest::Hello` from the client, validate `genesis_hash` +
//!    `chain_id` (wrong network ⇒ close), and reply with `SyncResponse::Hello` carrying the node's
//!    tip.
//! 2. For each `SyncRequest::GetBlocks{from,to}`: serve up to `SYNC_MAX_BATCH` blocks as a
//!    `SyncResponse::Blocks` of canonically-encoded `WireBlock`s.
//! 3. After the initial sync loop the gateway pushes live `SyncResponse::Blocks` (batch of 1) for
//!    each new block broadcast on the `newHeads` channel, so the client stays live without polling.
//!
//! ## Security properties
//! - **Read-only.** The gateway only reads from the chain; it never ingests gossip (that is
//!   `ingest_gossip_tx`, a different path). A light client submits txs via the normal
//!   `eth_sendRawTransaction` JSON-RPC, not through this gateway.
//! - **Bounded responses.** Every `GetBlocks` is clamped to `SYNC_MAX_BATCH = 128` blocks (AC-F8).
//! - **Wrong-network disconnect.** A `Hello` with a different `genesis_hash` or `chain_id` closes
//!   the connection immediately (AC-F-LN4).
//! - **The gateway is a thin adapter.** It carries `WireBlock` bytes verbatim; it never re-executes
//!   or validates the content. All verification happens in the light client's WASM kernel.

use std::net::SocketAddr;
use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio_tungstenite::{accept_async, tungstenite::Message};

use ubi2_network::consts::{PROTOCOL_VERSION, SYNC_MAX_BATCH};
use ubi2_network::wire::{Blocks, Genesis, Hello, SyncRequest, SyncResponse, WireBlock};

use crate::Chain;

/// Start the WebSocket sync gateway on `addr`. Returns a handle that shuts down when dropped.
///
/// Each accepted connection gets its own task. The gateway is read-only: it answers `Hello` +
/// `GetBlocks` and pushes live blocks; it never mutates chain state.
pub async fn serve_sync_gateway(
    addr: SocketAddr,
    chain: Chain,
) -> std::io::Result<SyncGatewayHandle> {
    let listener = TcpListener::bind(addr).await?;
    let (stop_tx, _) = broadcast::channel::<()>(1);
    let handle = SyncGatewayHandle {
        stop_tx: stop_tx.clone(),
    };

    let chain = Arc::new(chain);
    let stop_tx_accept = stop_tx.clone();
    tokio::spawn(async move {
        let mut stop_rx = stop_tx_accept.subscribe();
        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer)) => {
                            let chain_c = Arc::clone(&chain);
                            let mut stop_c = stop_tx.subscribe();
                            tokio::spawn(async move {
                                tokio::select! {
                                    _ = handle_connection(stream, peer, chain_c) => {}
                                    _ = stop_c.recv() => {}
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "sync gateway: accept error");
                        }
                    }
                }
                _ = stop_rx.recv() => break,
            }
        }
    });

    Ok(handle)
}

/// A handle to a running sync gateway. When dropped (or `stop()` called) the accept loop exits.
pub struct SyncGatewayHandle {
    stop_tx: broadcast::Sender<()>,
}

impl SyncGatewayHandle {
    /// Signal the gateway to stop accepting new connections and exit.
    pub fn stop(&self) {
        let _ = self.stop_tx.send(());
    }
}

impl Drop for SyncGatewayHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Handle one WebSocket connection: handshake, sync loop, live-push.
async fn handle_connection(stream: TcpStream, peer: SocketAddr, chain: Arc<Chain>) {
    tracing::debug!(%peer, "sync gateway: connection");
    let ws = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            tracing::debug!(%peer, error = %e, "sync gateway: WS handshake failed");
            return;
        }
    };

    if let Err(e) = run_session(ws, peer, chain).await {
        tracing::debug!(%peer, error = %e, "sync gateway: session ended");
    }
}

/// One session: Hello → GetBlocks loop → live-push.
async fn run_session(
    ws: tokio_tungstenite::WebSocketStream<TcpStream>,
    peer: SocketAddr,
    chain: Arc<Chain>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut sink, mut stream) = ws.split();

    // ---- Step 1: wait for the client's Hello ----
    let hello_bytes = loop {
        match stream.next().await {
            Some(Ok(Message::Binary(b))) => break b.to_vec(),
            Some(Ok(Message::Ping(d))) => {
                sink.send(Message::Pong(d)).await?;
            }
            Some(Ok(Message::Close(_))) | None => return Ok(()),
            Some(Ok(_)) => continue, // ignore text/pong frames
            Some(Err(e)) => return Err(Box::new(e)),
        }
    };

    let req = match SyncRequest::decode(&hello_bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(%peer, error = %e, "sync gateway: bad first message");
            return Ok(());
        }
    };

    let client_hello = match req {
        SyncRequest::Hello(h) => h,
        _ => {
            tracing::debug!(%peer, "sync gateway: expected Hello first");
            return Ok(());
        }
    };

    // Validate genesis_hash and chain_id — wrong network ⇒ close (AC-F-LN4).
    let our_genesis = chain.genesis_hash();
    let our_chain_id = chain.chain_id();
    if client_hello.genesis_hash != our_genesis || client_hello.chain_id != our_chain_id {
        tracing::debug!(
            %peer,
            client_genesis = %client_hello.genesis_hash,
            our_genesis = %our_genesis,
            "sync gateway: wrong network, closing"
        );
        sink.send(Message::Close(None)).await.ok();
        return Ok(());
    }

    // Reply with our Hello (tip + genesis).
    let (tip_h, tip_hash) = chain.tip();
    let our_hello = Hello {
        genesis_hash: our_genesis,
        chain_id: our_chain_id,
        tip: (tip_h, tip_hash),
        validator: None,
        peer_proof: vec![],
        protocol_ver: PROTOCOL_VERSION,
    };
    let resp = SyncResponse::Hello(our_hello);
    sink.send(Message::Binary(resp.encode())).await?;

    tracing::debug!(%peer, tip = tip_h, "sync gateway: hello exchange complete");

    // Subscribe to new heads BEFORE entering the request loop so we never miss a block.
    let mut heads_rx = chain.subscribe_heads();

    // ---- Step 2: serve GetBlocks requests and push live blocks ----
    loop {
        tokio::select! {
            // Inbound request from the client.
            msg = stream.next() => {
                match msg {
                    Some(Ok(Message::Binary(b))) => {
                        if let Err(e) = handle_request(b.as_ref(), &chain, &mut sink).await {
                            tracing::debug!(%peer, error = %e, "sync gateway: request error");
                            return Ok(());
                        }
                    }
                    Some(Ok(Message::Ping(d))) => { sink.send(Message::Pong(d)).await?; }
                    Some(Ok(Message::Close(_))) | None => return Ok(()),
                    Some(Ok(_)) => {}
                    Some(Err(e)) => return Err(Box::new(e)),
                }
            }

            // Live block pushed to light-client subscribers.
            block = heads_rx.recv() => {
                match block {
                    Ok(b) => {
                        let wb = block_to_wire(&b, &chain);
                        let resp = SyncResponse::Blocks(Blocks { blocks: vec![wb] });
                        if sink.send(Message::Binary(resp.encode())).await.is_err() {
                            return Ok(());
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => {
                        // Receiver fell behind — skip lost blocks; the client will request them.
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => return Ok(()),
                }
            }
        }
    }
}

/// Handle one `SyncRequest` from the client (expected: `GetBlocks`).
async fn handle_request(
    bytes: &[u8],
    chain: &Chain,
    sink: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let req = match SyncRequest::decode(bytes) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(error = %e, "sync gateway: bad request");
            return Ok(());
        }
    };

    match req {
        SyncRequest::GetBlocks(gb) => {
            // Clamp `to` by SYNC_MAX_BATCH (AC-F8 — bounds sync-response size).
            let from = gb.from;
            let to = gb.to.min(from.saturating_add(SYNC_MAX_BATCH - 1));
            let mut wire_blocks = Vec::new();
            for h in from..=to {
                match chain.block_at(h) {
                    Some(b) => wire_blocks.push(block_to_wire(&b, chain)),
                    None => break, // beyond tip
                }
            }
            let resp = SyncResponse::Blocks(Blocks {
                blocks: wire_blocks,
            });
            sink.send(Message::Binary(resp.encode())).await?;
        }
        // Spec 07 §3.4 (`ln-trust-2`): serve the seeded genesis anchor — the block-0 hash, the seeded
        // `state_root`, genesis time, the authorized PoA proposer, and the canonical genesis state
        // snapshot. The light client re-derives the snapshot's root locally and rejects unless it equals
        // its PINNED constant (so a lying gateway is caught). If the node never sealed its genesis anchor
        // (no light-client surface configured), we drop the connection — we never serve an empty/zero
        // anchor that the client could mistake for a real seeded genesis (fail-closed).
        SyncRequest::GetGenesis(_) => match chain.genesis_anchor() {
            Some(anchor) => {
                let resp = SyncResponse::Genesis(Genesis {
                    genesis_hash: chain.genesis_hash(),
                    chain_id: chain.chain_id(),
                    state_root: anchor.state_root,
                    genesis_time: chain.genesis_time(),
                    proposer: chain.genesis_proposer().unwrap_or_default(),
                    snapshot: anchor.snapshot,
                });
                sink.send(Message::Binary(resp.encode())).await?;
            }
            None => {
                tracing::debug!("sync gateway: GetGenesis but no sealed genesis anchor; closing");
                sink.send(Message::Close(None)).await.ok();
            }
        },
        // A second Hello is a no-op (clients may re-send after a network hiccup).
        SyncRequest::Hello(_) => {}
    }
    Ok(())
}

/// Convert a `crates/rpc::Block` to a `WireBlock` for serving over the sync gateway. The raw user
/// txs are retrieved from the chain's `raw_tx` cache. A block whose raw txs are not cached (e.g. a
/// genesis block or one produced before the cache was populated) gets an empty tx list — its
/// `state_root` is still served faithfully, and the `txs_root` over zero txs matches.
fn block_to_wire(block: &crate::Block, chain: &Chain) -> WireBlock {
    let raw_txs = chain.raw_txs_for_block(block);
    WireBlock {
        number: block.number,
        parent_hash: block.parent_hash,
        timestamp: block.timestamp,
        txs_root: block.txs_root,
        state_root: block.state_root,
        proposer: block.proposer,
        proposer_sig: block.proposer_sig.clone(),
        txs: raw_txs,
    }
}
