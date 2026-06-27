//! In-process two-node integration test (the Phase-2 DoD bar):
//!
//! 1. Two [`NetworkHandle`] instances start on **non-default, OS-assigned** TCP ports (`tcp/0`), with
//!    **mDNS off** — node B dials node A's bound multiaddr **explicitly**, so connectivity is
//!    deterministic (no reliance on mDNS, §1).
//! 2. A `publish_tx` from A is **received by B** (gossip); a **repeat publish of the same tx is deduped**
//!    by gossipsub's message-id (= the tx hash, §3.1) and is NOT delivered a second time.
//! 3. A `request_blocks` from B to A **round-trips a small batch** over the `ubi2/sync/1`
//!    request-response protocol (§4.2).
//! 4. The `Hello` handshake is exchanged on connect (§4.1) and the PeerId↔validator binding verifies.
//!
//! Ports are non-default (OS-assigned) and the test runtime is torn down at the end (no live node lingers).

use std::time::Duration;

use alloy_primitives::{keccak256, Address, B256};
use libp2p::Multiaddr;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;

use ubi2_network::config::{NetworkConfig, ValidatorKey};
use ubi2_network::wire::{Blocks, GetBlocks, WireBlock};
use ubi2_network::{start, NetEvent, NetworkHandle};

const CHAIN_ID: u64 = 0x5542;

fn genesis() -> B256 {
    B256::repeat_byte(0x42)
}

/// Build a node config: a fresh transport keypair, an OS-assigned loopback TCP port, mDNS OFF, a fast
/// gossip heartbeat (so the mesh forms quickly in the test), and a validator key.
fn node_config(validator_secret: [u8; 32]) -> NetworkConfig {
    NetworkConfig::new(CHAIN_ID, genesis())
        .with_validator_key(ValidatorKey::from_bytes(&validator_secret).unwrap())
        .with_mdns(false)
        .with_gossip_heartbeat(Duration::from_millis(200))
}

/// Drain events until one matching `pred` arrives (or time out). Returns the matched event.
async fn wait_for<F>(rx: &mut UnboundedReceiver<NetEvent>, mut pred: F, label: &str) -> NetEvent
where
    F: FnMut(&NetEvent) -> bool,
{
    let fut = async {
        loop {
            match rx.recv().await {
                Some(ev) if pred(&ev) => break ev,
                Some(_) => continue,
                None => panic!("{label}: event stream closed"),
            }
        }
    };
    timeout(Duration::from_secs(10), fut)
        .await
        .unwrap_or_else(|_| panic!("{label}: timed out"))
}

/// The bound listen multiaddr from the first `Listening` event.
async fn first_listen_addr(rx: &mut UnboundedReceiver<NetEvent>) -> Multiaddr {
    match wait_for(rx, |e| matches!(e, NetEvent::Listening { .. }), "listen").await {
        NetEvent::Listening { addr } => addr,
        _ => unreachable!(),
    }
}

fn mk_block(n: u64) -> WireBlock {
    let mut b = WireBlock {
        number: n,
        parent_hash: B256::repeat_byte(n as u8),
        timestamp: 1_700_000_000 + n,
        txs_root: B256::ZERO,
        state_root: B256::repeat_byte((n + 1) as u8),
        proposer: Address::ZERO,
        proposer_sig: vec![],
        txs: vec![vec![n as u8; 8]],
    };
    b.txs_root = b.recompute_txs_root();
    b
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_connect_gossip_tx_and_sync_blocks() {
    // --- start both nodes (non-default OS-assigned ports, mDNS off) ---
    let (handle_a, mut rx_a): (NetworkHandle, _) = start(node_config([0x11; 32])).unwrap();
    let (handle_b, mut rx_b): (NetworkHandle, _) = start(node_config([0x22; 32])).unwrap();

    // Append node A's PeerId to its listen addr so B dials a fully-qualified `/p2p/...` multiaddr.
    let a_addr = first_listen_addr(&mut rx_a).await;
    let _ = first_listen_addr(&mut rx_b).await;
    let a_dial: Multiaddr = format!("{a_addr}/p2p/{}", handle_a.local_peer_id())
        .parse()
        .unwrap();

    // --- B dials A explicitly (no mDNS) ---
    handle_b.dial(a_dial);

    // Both sides observe the connection.
    wait_for(
        &mut rx_a,
        |e| matches!(e, NetEvent::PeerConnected { .. }),
        "A: peer connected",
    )
    .await;
    wait_for(
        &mut rx_b,
        |e| matches!(e, NetEvent::PeerConnected { .. }),
        "B: peer connected",
    )
    .await;

    // --- handshake: B (the dialer) sends Hello, A receives it; A's Hello returns to B. Verify the
    //     PeerId<->validator binding on the receiver side (§4.1). ---
    let b_validator = ValidatorKey::from_bytes(&[0x22; 32]).unwrap().address();
    match wait_for(
        &mut rx_a,
        |e| matches!(e, NetEvent::Hello { .. }),
        "A: hello",
    )
    .await
    {
        NetEvent::Hello { peer, hello } => {
            assert_eq!(hello.genesis_hash, genesis(), "genesis must match");
            assert_eq!(hello.chain_id, CHAIN_ID);
            // The binding recovers B's validator address from the proof over (peerId ‖ genesis).
            let bound = hello.verify_binding(&peer.to_bytes());
            assert_eq!(
                bound,
                Some(b_validator),
                "PeerId<->validator binding must verify"
            );
        }
        _ => unreachable!(),
    }
    // B receives A's Hello in return.
    wait_for(
        &mut rx_b,
        |e| matches!(e, NetEvent::Hello { .. }),
        "B: hello",
    )
    .await;

    // Let the gossipsub mesh form (heartbeat is 200ms; give it a few cycles).
    tokio::time::sleep(Duration::from_millis(800)).await;

    // --- gossip a tx from A; B receives it; a repeat is deduped ---
    let raw_tx = vec![0x02u8, 0xde, 0xad, 0xbe, 0xef, 0x01];
    let tx_hash = keccak256(&raw_tx);
    handle_a.publish_tx(raw_tx.clone());

    match wait_for(
        &mut rx_b,
        |e| matches!(e, NetEvent::TxReceived { .. }),
        "B: tx received",
    )
    .await
    {
        NetEvent::TxReceived { id, raw, .. } => {
            assert_eq!(id, tx_hash, "message-id must equal the tx hash (§3.1)");
            assert_eq!(raw, raw_tx, "the raw RLP bytes must be delivered verbatim");
        }
        _ => unreachable!(),
    }

    // Re-publish the SAME tx: gossipsub dedups by message-id, so B must NOT see a second TxReceived.
    handle_a.publish_tx(raw_tx.clone());
    let dup = timeout(Duration::from_millis(800), async {
        loop {
            match rx_b.recv().await {
                Some(NetEvent::TxReceived { .. }) => break true,
                Some(_) => continue,
                None => break false,
            }
        }
    })
    .await;
    assert!(
        dup.is_err(),
        "a duplicate tx must be deduped (no second TxReceived)"
    );

    // --- request_blocks round-trips a small batch: B asks A for [1,3]; A responds with 3 blocks ---
    let peer_a = handle_a.local_peer_id();
    let reply_id = handle_b.request_blocks(peer_a, GetBlocks { from: 1, to: 3 });

    // A serves the request.
    let responder = match wait_for(
        &mut rx_a,
        |e| matches!(e, NetEvent::SyncRequest { .. }),
        "A: sync request",
    )
    .await
    {
        NetEvent::SyncRequest { request, token, .. } => {
            assert_eq!(request, GetBlocks { from: 1, to: 3 });
            token
        }
        _ => unreachable!(),
    };
    let served = Blocks {
        blocks: vec![mk_block(1), mk_block(2), mk_block(3)],
    };
    handle_a.respond_blocks(responder, served.clone());

    // B receives the response, correlated by reply_id.
    match wait_for(
        &mut rx_b,
        |e| matches!(e, NetEvent::SyncResponse { .. }),
        "B: sync response",
    )
    .await
    {
        NetEvent::SyncResponse {
            request_id, blocks, ..
        } => {
            assert_eq!(request_id, reply_id, "response correlates to the request");
            assert_eq!(blocks.blocks.len(), 3);
            assert_eq!(*blocks, served, "the batch round-trips byte-identically");
        }
        _ => unreachable!(),
    }

    // Tidy up: drop the handles so the swarm loops shut down before the runtime is torn down.
    drop(handle_a);
    drop(handle_b);
}

/// A second node that gossips a BLOCK; the peer receives it and `shallow_verify` passes (txs_root +
/// proposer-sig check, §3.1). Exercises the `ubi2/block/1` topic end-to-end.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn block_gossip_delivers_and_shallow_verifies() {
    let (handle_a, mut rx_a) = start(node_config([0x33; 32])).unwrap();
    let (handle_b, mut rx_b) = start(node_config([0x44; 32])).unwrap();

    let a_addr = first_listen_addr(&mut rx_a).await;
    let _ = first_listen_addr(&mut rx_b).await;
    let a_dial: Multiaddr = format!("{a_addr}/p2p/{}", handle_a.local_peer_id())
        .parse()
        .unwrap();
    handle_b.dial(a_dial);

    wait_for(
        &mut rx_a,
        |e| matches!(e, NetEvent::PeerConnected { .. }),
        "A: connected",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    let block = mk_block(7);
    let want_hash = block.hash();
    handle_a.publish_block(block.clone());

    match wait_for(
        &mut rx_b,
        |e| matches!(e, NetEvent::BlockReceived { .. }),
        "B: block received",
    )
    .await
    {
        NetEvent::BlockReceived { id, block: got, .. } => {
            assert_eq!(id, want_hash, "block message-id = block hash (§3.1)");
            assert_eq!(*got, block, "the block round-trips byte-identically");
            assert!(got.shallow_verify(), "delivered block shallow-verifies");
        }
        _ => unreachable!(),
    }

    drop(handle_a);
    drop(handle_b);
}
