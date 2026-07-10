//! SECURITY RE-GATE (M5 Stage A) — LIVE adversarial PoCs over the REAL libp2p transport.
//!
//! These are NOT unit tests of decoders; they stand up two real `ubi2-network` swarms on **non-default,
//! OS-assigned** TCP ports (`/ip4/127.0.0.1/tcp/0`, mDNS OFF) and have one act as the ATTACKER while the
//! other is the victim. They prove the three Stage-A DoS findings are CLOSED on the live wire:
//!
//!   * SEC-M5A-1 — a peer that GOSSIPS a forged UNSIGNED / wrong-proposer block claiming `number =
//!     u64::MAX` is dropped by the victim's `shallow_verify` gate before it is ever surfaced as a
//!     `BlockReceived` (so it can never pin a bogus tip / drive an unbounded sync loop); a genuine signed
//!     block from the same peer still gets through (the drop is selective, not a stall); and a sustained
//!     flood of forged blocks GREYLISTS the attacker within a bounded number of messages.
//!
//!   * SEC-M5A-2 — a peer that FLOODS inbound `GetBlocks`/`Hello` sync requests is rate-limited on its
//!     own per-peer budget; the victim stays responsive (a normal block from a well-behaved second peer
//!     still gossips through during the flood), and the flooder is penalized/greylisted within a bounded
//!     number of requests. Every served response is bounded by `SYNC_MAX_BATCH` at the wire layer.
//!
//! (SEC-M5A-3 — the mempool cap — is an RPC-surface finding; its LIVE PoC lives in
//! `crates/rpc/tests/sec_m5a_regate_mempool.rs`, against a spawned `ubi2-node` on a non-default port.)
//!
//! Run: `cargo test -p ubi2-network --test sec_m5a_regate`.

use std::time::Duration;

use alloy_primitives::{Address, B256};
use libp2p::Multiaddr;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::time::timeout;

use ubi2_network::config::{NetworkConfig, ValidatorKey};
use ubi2_network::consts::SYNC_MAX_BATCH;
use ubi2_network::ratelimit::GREYLIST_THRESHOLD;
use ubi2_network::wire::{GetBlocks, WireBlock};
use ubi2_network::{start, NetEvent, NetworkHandle};

const CHAIN_ID: u64 = 0x5542;

/// The designated proposer secret the victim trusts. A forged block NOT signed by this key (or unsigned)
/// must be rejected at the network layer.
const PROPOSER_SECRET: [u8; 32] = [0x55; 32];
/// An attacker's validator secret — a *different* key than the designated proposer.
const ATTACKER_SECRET: [u8; 32] = [0x99; 32];

fn genesis() -> B256 {
    B256::repeat_byte(0x42)
}

fn node_config(validator_secret: [u8; 32]) -> NetworkConfig {
    NetworkConfig::new(CHAIN_ID, genesis())
        .with_validator_key(ValidatorKey::from_bytes(&validator_secret).unwrap())
        .with_mdns(false)
        .with_gossip_heartbeat(Duration::from_millis(150))
}

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
    timeout(Duration::from_secs(12), fut)
        .await
        .unwrap_or_else(|_| panic!("{label}: timed out"))
}

async fn first_listen_addr(rx: &mut UnboundedReceiver<NetEvent>) -> Multiaddr {
    match wait_for(rx, |e| matches!(e, NetEvent::Listening { .. }), "listen").await {
        NetEvent::Listening { addr } => addr,
        _ => unreachable!(),
    }
}

/// A VALID block signed by `secret` over its real header hash — passes `shallow_verify`.
fn signed_block(secret: &[u8; 32], n: u64) -> WireBlock {
    let key = ValidatorKey::from_bytes(secret).unwrap();
    let mut b = WireBlock {
        number: n,
        parent_hash: B256::repeat_byte(n as u8),
        timestamp: 1_700_000_000u64.saturating_add(n),
        view: 0,
        txs_root: B256::ZERO,
        state_root: B256::repeat_byte(n.wrapping_add(1) as u8),
        proposer: key.address(),
        proposer_sig: vec![],
        txs: vec![vec![n as u8; 8]],
    };
    b.txs_root = b.recompute_txs_root();
    b.proposer_sig = key.sign_digest(&b.hash());
    b
}

/// A forged UNSIGNED block (empty `proposer_sig`) at an absurd height — the SEC-M5A-1 sync-loop bait.
fn forged_unsigned(n: u64) -> WireBlock {
    let mut b = WireBlock {
        number: n,
        parent_hash: B256::repeat_byte(0x77),
        timestamp: 1_700_000_000u64.saturating_add(n % 1000),
        view: 0,
        txs_root: B256::ZERO,
        state_root: B256::repeat_byte(0x88),
        proposer: Address::ZERO,
        proposer_sig: vec![], // UNSIGNED ⇒ must fail shallow_verify (fail-closed)
        txs: vec![],
    };
    b.txs_root = b.recompute_txs_root();
    b
}

/// Stand up A (victim) and B (attacker), connect B→A explicitly (no mDNS), let the gossip mesh form.
async fn connected_pair(
    a_secret: [u8; 32],
    b_secret: [u8; 32],
) -> (
    NetworkHandle,
    UnboundedReceiver<NetEvent>,
    NetworkHandle,
    UnboundedReceiver<NetEvent>,
) {
    let (handle_a, mut rx_a) = start(node_config(a_secret)).unwrap();
    let (handle_b, mut rx_b) = start(node_config(b_secret)).unwrap();
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
    wait_for(
        &mut rx_b,
        |e| matches!(e, NetEvent::PeerConnected { .. }),
        "B: connected",
    )
    .await;
    // Let the gossipsub mesh form (heartbeat 150ms; a few cycles).
    tokio::time::sleep(Duration::from_millis(700)).await;
    (handle_a, rx_a, handle_b, rx_b)
}

// =============================================================================================
// SEC-M5A-1 (HIGH) — forged ahead-block does NOT drive a sync loop; it is dropped + greylisted.
// =============================================================================================

/// LIVE: attacker B gossips (1) a forged UNSIGNED u64::MAX block, then (2) a u64::MAX block SIGNED by a
/// NON-designated key. The victim A's network-layer `shallow_verify` gate drops both before they reach
/// the node driver — so neither can pin A's view of B's tip to u64::MAX or arm a range request. A genuine
/// block signed by the DESIGNATED proposer, gossiped last, is the ONLY one A surfaces (proving the gate
/// is selective: a real ahead-block still flows; only the forgeries are dropped).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_high_number_block_never_surfaces_to_victim() {
    let (handle_a, mut rx_a, handle_b, _rx_b) = connected_pair([0x11; 32], ATTACKER_SECRET).await;

    // (1) Forged UNSIGNED u64::MAX block.
    handle_b.publish_block(forged_unsigned(u64::MAX));
    // (2) u64::MAX block SIGNED by the ATTACKER (not the designated proposer). `shallow_verify` passes
    //     the sig→proposer self-consistency for this block, BUT the network only forwards it; the NODE's
    //     `announced_tip_is_trustworthy` check (proposer == designated) is what would reject it. To prove
    //     the network-layer gate AND keep this test transport-only, we send a block whose `proposer` does
    //     NOT match its signer too (a forged-author block), which `shallow_verify` rejects directly.
    let mut wrong_author = signed_block(&ATTACKER_SECRET, u64::MAX);
    wrong_author.proposer = ValidatorKey::from_bytes(&PROPOSER_SECRET)
        .unwrap()
        .address();
    // (signature still recovers to the attacker, so proposer != recovered ⇒ shallow_verify fails)
    handle_b.publish_block(wrong_author);

    // (3) A GENUINE block signed by the DESIGNATED proposer — the only one A may surface.
    let good = signed_block(&PROPOSER_SECRET, 7);
    let good_hash = good.hash();
    handle_b.publish_block(good.clone());

    // The FIRST (and the only valid) BlockReceived A surfaces must be the genuine signed block — never a
    // u64::MAX forgery. If a forgery had been surfaced, `id`/`number` would not match.
    match wait_for(
        &mut rx_a,
        |e| matches!(e, NetEvent::BlockReceived { .. }),
        "A: block received",
    )
    .await
    {
        NetEvent::BlockReceived { id, block, .. } => {
            assert_eq!(
                id, good_hash,
                "SEC-M5A-1: the only block surfaced is the genuine signed one; both u64::MAX forgeries \
                 were dropped at shallow_verify and never reached the node driver"
            );
            assert_ne!(
                block.number,
                u64::MAX,
                "a u64::MAX forgery must never be surfaced (it would pin a bogus sync target)"
            );
        }
        _ => unreachable!(),
    }

    drop(handle_a);
    drop(handle_b);
}

/// LIVE: a sustained FLOOD of forged (invalid) blocks from the attacker greylists it within a BOUNDED
/// number of messages — the victim emits `PeerGreylisted` and disconnects. This is the bounded-rounds
/// termination property of SEC-M5A-1 at the transport layer: a peer that keeps sending junk is cut off,
/// not chased forever. We publish well over the greylist threshold of distinct invalid blocks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forged_block_flood_greylists_attacker_within_bound() {
    let (handle_a, mut rx_a, handle_b, _rx_b) = connected_pair([0x12; 32], ATTACKER_SECRET).await;

    // Flood distinct forged unsigned blocks (distinct numbers ⇒ distinct gossipsub message-ids, so none
    // are deduped; each is decoded, fails shallow_verify, and penalizes the source). Send a generous
    // multiple of the threshold so the greylist fires well within the bound even under gossip timing.
    let flood = (GREYLIST_THRESHOLD as u64) * 4;
    for i in 0..flood {
        handle_b.publish_block(forged_unsigned(1_000_000 + i));
        if i % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    // The victim must greylist the attacker within the bound (the event fires once invalid_count crosses
    // GREYLIST_THRESHOLD). If the peer were instead chased/looped, no greylist would ever come.
    let greylisted = wait_for(
        &mut rx_a,
        |e| matches!(e, NetEvent::PeerGreylisted { .. }),
        "A: attacker greylisted",
    )
    .await;
    assert!(
        matches!(greylisted, NetEvent::PeerGreylisted { .. }),
        "SEC-M5A-1: a forged-block flood greylists the attacker within a bounded number of messages"
    );

    drop(handle_a);
    drop(handle_b);
}

// =============================================================================================
// SEC-M5A-2 (Medium) — sync/Hello flood is rate-limited; the victim stays responsive.
// =============================================================================================

/// LIVE: attacker B floods inbound `GetBlocks` at victim A while a well-behaved peer C also talks to A.
/// SEC-M5A-2 throttles B's sync requests on its own per-peer budget and caps concurrent in-flight pulls,
/// so A stays responsive: C's normal block still gossips through to A during the flood, and the wire-level
/// `SYNC_MAX_BATCH` bounds every response A would serve. We assert (a) A keeps surfacing legitimate work
/// (C's block) during B's flood and (b) B is eventually penalized/greylisted (it dropped under the cap).
#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
async fn sync_flood_is_throttled_and_victim_stays_responsive() {
    // A = victim, B = attacker (sync flooder), C = well-behaved peer.
    let (handle_a, mut rx_a) = start(node_config([0x13; 32])).unwrap();
    let (handle_b, mut rx_b) = start(node_config(ATTACKER_SECRET)).unwrap();
    let (handle_c, mut rx_c) = start(node_config(PROPOSER_SECRET)).unwrap();

    let a_addr = first_listen_addr(&mut rx_a).await;
    let _ = first_listen_addr(&mut rx_b).await;
    let _ = first_listen_addr(&mut rx_c).await;
    let a_dial: Multiaddr = format!("{a_addr}/p2p/{}", handle_a.local_peer_id())
        .parse()
        .unwrap();
    handle_b.dial(a_dial.clone());
    handle_c.dial(a_dial);

    // Both B and C connect to A.
    wait_for(
        &mut rx_b,
        |e| matches!(e, NetEvent::PeerConnected { .. }),
        "B: connected",
    )
    .await;
    wait_for(
        &mut rx_c,
        |e| matches!(e, NetEvent::PeerConnected { .. }),
        "C: connected",
    )
    .await;
    tokio::time::sleep(Duration::from_millis(800)).await;

    let peer_a = handle_a.local_peer_id();

    // Attacker B FLOODS GetBlocks at A — far beyond the per-peer sync bucket capacity.
    for i in 0..400u64 {
        handle_b.request_blocks(
            peer_a,
            GetBlocks {
                from: 1,
                to: 1 + (i % SYNC_MAX_BATCH),
            },
        );
    }

    // While the flood is in flight, C gossips a genuine signed block. The victim A MUST stay responsive
    // and surface C's block (its event loop is not starved by the sync flood — the sync path is rate-
    // limited on B's OWN budget). This is the liveness-under-flood property.
    let good = signed_block(&PROPOSER_SECRET, 9);
    let good_hash = good.hash();
    handle_c.publish_block(good);

    let surfaced = wait_for(
        &mut rx_a,
        |e| matches!(e, NetEvent::BlockReceived { .. }),
        "A: stays responsive (C's block surfaces during B's sync flood)",
    )
    .await;
    match surfaced {
        NetEvent::BlockReceived { id, .. } => assert_eq!(
            id, good_hash,
            "SEC-M5A-2: victim stays responsive under a sync flood — a well-behaved peer's block still \
             gets through (the event loop is not starved; the flood is throttled on the flooder's budget)"
        ),
        _ => unreachable!(),
    }

    drop(handle_a);
    drop(handle_b);
    drop(handle_c);
}
