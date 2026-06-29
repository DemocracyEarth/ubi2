//! Sync gateway + light client integration test (spec 07 §3.2, ADR-0006 Decision 2).
//!
//! Tests:
//!   1. A light client (driven by `LightCore`, the pure-Rust equivalent of the WASM kernel) connects
//!      to the WS sync gateway, handshakes, and syncs blocks via `GetBlocks`. The light client's
//!      `state_root` after syncing **byte-identically equals** the full node's (AC-LC2 / AC-WB).
//!   2. A verified human's `balanceOf` from the light client's locally re-executed state matches the
//!      full node at the same block timestamp (AC-LC3).
//!   3. A **tampered block** (mutated `state_root`) is **rejected** by `LightCore.apply_block` — the
//!      tip does NOT advance and the error message confirms `state_root mismatch` (AC-F-LN1).
//!   4. A **wrong-network** gateway (different `genesis_hash`) closes the connection at the Hello
//!      exchange (AC-F-LN4).
//!
//! Design: runs in-process so the test is self-contained and fast.  Uses `LightCore` directly (the
//! same kernel `crates/runtime-wasm/src/kernel.rs` exports for the WASM build) rather than an actual
//! `.wasm` artifact — the parity test (`crates/runtime-wasm/tests/parity.rs`, AC-WB) already proved
//! that `LightCore` and `crates/rpc::Chain` produce byte-identical `state_root`s.
//!
//! Run with: `cargo test -p ubi2-node --test sync_gateway -- --ignored`

use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy_primitives::address;
use futures_util::{SinkExt, StreamExt};
use tokio_tungstenite::{connect_async, tungstenite::Message};

use ubi2_network::consts::PROTOCOL_VERSION;
use ubi2_network::wire::{GetBlocks, Hello, SyncRequest, SyncResponse};
use ubi2_rpc::{serve_sync_gateway, Block, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, UBI};
use ubi2_runtime_wasm::kernel::LightCore;

// ─── Ports (non-default, no clash with other tests) ───────────────────────────
const SYNC_PORT: u16 = 19800;
const WRONG_NET_PORT: u16 = 19801;

// ─── Devnet constants ────────────────────────────────────────────────────────
const GENESIS_TIME: u64 = 1_700_100_000;
const DEV_ADDR: alloy_primitives::Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
// Proposer key: Hardhat/Anvil account #0 (PUBLIC — non-secret devnet key).
const PROPOSER_SECRET: [u8; 32] = {
    let b = b"ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
};

const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Build a test chain seeded with a dev verified human (mirrors main.rs genesis). Returns the
/// chain and the "anchor" block (the first block after seeding, which commits the seeded state).
fn make_test_chain() -> (Chain, Block) {
    let key = Arc::new(ProposerKey::from_bytes(&PROPOSER_SECRET).expect("proposer key"));
    let chain = Chain::new(DEVNET_CHAIN_ID, GENESIS_TIME).with_proposer_key(key);
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: GENESIS_TIME,
        last_settled_at: GENESIS_TIME,
        settled_balance: 100 * UBI, // start with a balance so balance checks are non-trivial
        nonce: 0,
    });
    chain.seed_verified_human(&DEV_ADDR.into_array(), GENESIS_TIME);
    // Produce one empty anchor block to commit the seeded state to a real `state_root`.
    let anchor = chain.produce_block(GENESIS_TIME + 2);
    (chain, anchor)
}

/// Build a `LightCore` whose verified state equals the server's at `anchor`, by importing the
/// server's anchor state via the wrapper's snapshot format (same technique as the AC-WB parity test).
fn build_light_at_anchor(chain: &Chain, anchor: &Block) -> LightCore {
    let server_snap = chain.export_snapshot();
    let server_json = serde_json::to_value(&server_snap).unwrap();
    let state = server_json
        .get("state")
        .expect("server snapshot has state section")
        .clone();
    let light_snap = serde_json::json!({
        "version": 1,
        "chain_id": DEVNET_CHAIN_ID,
        "tip": {
            "number": anchor.number,
            "hash": hex32(&anchor.hash.0),
            "state_root": hex32(&anchor.state_root.0),
            "timestamp": anchor.timestamp,
        },
        "state": state,
    });
    let bytes = serde_json::to_vec(&light_snap).unwrap();
    LightCore::deserialize(&bytes).expect("browser imports server anchor state")
}

/// Poll a TCP port until it accepts or timeout elapses.
fn wait_port(port: u16, timeout: Duration) -> bool {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

// ─── Wire client helpers ──────────────────────────────────────────────────────

async fn send_req(
    sink: &mut (impl SinkExt<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin),
    req: &SyncRequest,
) {
    sink.send(Message::Binary(req.encode()))
        .await
        .expect("send sync request");
}

async fn recv_resp(
    stream: &mut (impl StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin),
) -> SyncResponse {
    loop {
        match stream.next().await.expect("stream open") {
            Ok(Message::Binary(b)) => {
                return SyncResponse::decode(&b).expect("decode SyncResponse")
            }
            Ok(Message::Ping(_)) | Ok(Message::Pong(_)) | Ok(Message::Text(_)) => continue,
            other => panic!("unexpected WS frame: {other:?}"),
        }
    }
}

// ─── Test 1: sync and verify ──────────────────────────────────────────────────

/// Boot chain + gateway; light client syncs blocks, asserts state_root match; verifies tampered
/// block is rejected.
#[tokio::test]
#[ignore]
async fn sync_and_verify() {
    let (chain, anchor) = make_test_chain();

    // Produce 4 more blocks above the anchor (total: 5 blocks, heights 1..5).
    let mut last_ts = GENESIS_TIME + 2;
    for i in 0..4u64 {
        let ts = GENESIS_TIME + 2 + (i + 1) * 2;
        chain.produce_block(ts);
        last_ts = ts;
    }
    let (tip_h, _) = chain.tip();
    assert_eq!(tip_h, 5, "should have 5 blocks");

    let node_state_root = chain.state_root();
    let genesis_hash = chain.genesis_hash();

    // ---- Start the sync gateway ----
    let sync_addr: SocketAddr = format!("127.0.0.1:{SYNC_PORT}").parse().unwrap();
    let _gw = serve_sync_gateway(sync_addr, chain.clone())
        .await
        .expect("start sync gateway");
    assert!(
        wait_port(SYNC_PORT, Duration::from_secs(3)),
        "gateway did not start"
    );

    // ---- Connect to the gateway ----
    let (ws, _) = connect_async(format!("ws://127.0.0.1:{SYNC_PORT}"))
        .await
        .expect("ws connect");
    let (mut sink, mut stream) = ws.split();

    // Hello handshake.
    send_req(
        &mut sink,
        &SyncRequest::Hello(Hello {
            genesis_hash,
            chain_id: DEVNET_CHAIN_ID,
            tip: (0, alloy_primitives::B256::ZERO),
            validator: None,
            peer_proof: vec![],
            protocol_ver: PROTOCOL_VERSION,
        }),
    )
    .await;

    let resp = recv_resp(&mut stream).await;
    let gw_hello = match resp {
        SyncResponse::Hello(h) => h,
        other => panic!("expected Hello, got {other:?}"),
    };
    assert_eq!(gw_hello.chain_id, DEVNET_CHAIN_ID, "chain_id must match");
    assert_eq!(
        gw_hello.genesis_hash, genesis_hash,
        "genesis_hash must match"
    );
    assert_eq!(gw_hello.tip.0, 5, "gateway tip must be 5");

    // ---- Build the LightCore at the anchor (block 1) ----
    let mut lc = build_light_at_anchor(&chain, &anchor);
    assert_eq!(lc.tip().number, 1, "LightCore starts at anchor (block 1)");
    assert_eq!(
        lc.state_root(),
        anchor.state_root.0,
        "LightCore anchor state_root must equal server"
    );

    // ---- Request blocks 2→5 (above the anchor) ----
    send_req(
        &mut sink,
        &SyncRequest::GetBlocks(GetBlocks { from: 2, to: 5 }),
    )
    .await;

    let resp = recv_resp(&mut stream).await;
    let wire_blocks = match resp {
        SyncResponse::Blocks(b) => b.blocks,
        other => panic!("expected Blocks, got {other:?}"),
    };
    assert_eq!(wire_blocks.len(), 4, "should receive blocks 2..5");

    // ---- Drive LightCore through each block; assert state_root parity ----
    for (i, wb) in wire_blocks.iter().enumerate() {
        let wb_bytes = wb.encode();
        let outcome = lc
            .apply_block(&wb_bytes, None)
            .unwrap_or_else(|e| panic!("LightCore.apply_block failed at block {}: {e}", i + 2));
        assert_eq!(outcome.number, (i + 2) as u64, "block number must match");
        // Per-block parity check against the full node's committed state_root.
        let server_root = chain
            .state_root_at(outcome.number)
            .expect("server has this height")
            .0;
        assert_eq!(
            lc.state_root(),
            server_root,
            "light client state_root diverged from server at block {}",
            outcome.number
        );
    }

    // ---- Assert 1: final state_root byte-identical (AC-LC2 / AC-WB) ----
    assert_eq!(
        lc.state_root(),
        node_state_root.0,
        "light client state_root must byte-identically equal full node (AC-LC2 / AC-WB)"
    );

    // ---- Assert 2: balanceOf(DEV_ADDR) matches (AC-LC3) ----
    let lc_balance = lc.balance_of(&DEV_ADDR.into_array(), last_ts);
    let node_balance = chain.balance(&DEV_ADDR.into_array(), last_ts);
    assert_eq!(
        lc_balance, node_balance,
        "light client balanceOf must match full node (AC-LC3)"
    );

    // ---- Assert 3: tampered block is rejected (AC-F-LN1) ----
    // Re-request block 5 and mutate its state_root.
    send_req(
        &mut sink,
        &SyncRequest::GetBlocks(GetBlocks { from: 5, to: 5 }),
    )
    .await;
    let resp = recv_resp(&mut stream).await;
    let tampered_blocks = match resp {
        SyncResponse::Blocks(b) => b.blocks,
        other => panic!("expected Blocks for tampered test, got {other:?}"),
    };
    let mut tampered = tampered_blocks[0].clone();
    let mut bad_root = tampered.state_root.0;
    bad_root[0] ^= 0xff; // flip a bit — the re-executed root will differ
    tampered.state_root = alloy_primitives::B256::from(bad_root);
    let tampered_bytes = tampered.encode();

    // Apply to a fresh LightCore at block 4 (just below the tampered block's height).
    let mut lc_tamper = build_light_at_anchor(&chain, &anchor);
    // Sync it to block 4 first.
    send_req(
        &mut sink,
        &SyncRequest::GetBlocks(GetBlocks { from: 2, to: 4 }),
    )
    .await;
    let resp = recv_resp(&mut stream).await;
    let blocks_2_4 = match resp {
        SyncResponse::Blocks(b) => b.blocks,
        other => panic!("expected Blocks 2..4, got {other:?}"),
    };
    for wb in &blocks_2_4 {
        lc_tamper
            .apply_block(&wb.encode(), None)
            .expect("apply 2..4");
    }
    assert_eq!(
        lc_tamper.tip().number,
        4,
        "tamper-test core must be at block 4"
    );

    // Now try the tampered block 5.
    let reject_err = lc_tamper.apply_block(&tampered_bytes, None);
    assert!(
        reject_err.is_err(),
        "tampered block must be rejected (AC-F-LN1)"
    );
    let err_msg = reject_err.unwrap_err().to_string();
    assert!(
        err_msg.contains("state_root mismatch") || err_msg.contains("shallow-verify"),
        "unexpected rejection reason: {err_msg}"
    );
    assert_eq!(
        lc_tamper.tip().number,
        4,
        "tip must not advance on a rejected block"
    );

    println!("[sync_and_verify] PASS:");
    println!("  state_root = {}", hex32(&lc.state_root()));
    println!("  balanceOf(DEV_ADDR) = {lc_balance} == node = {node_balance}");
    println!("  tampered block rejected: {err_msg}");
}

// ─── Test 2: wrong-network gateway is rejected ────────────────────────────────

/// A gateway on a different network (wrong genesis_hash or chain_id) must close the connection
/// at the Hello exchange (AC-F-LN4).
#[tokio::test]
#[ignore]
async fn wrong_network_rejected() {
    let (chain, _anchor) = make_test_chain();
    chain.produce_block(GENESIS_TIME + 2);

    let sync_addr: SocketAddr = format!("127.0.0.1:{WRONG_NET_PORT}").parse().unwrap();
    let _gw = serve_sync_gateway(sync_addr, chain.clone())
        .await
        .expect("start gateway");
    assert!(
        wait_port(WRONG_NET_PORT, Duration::from_secs(3)),
        "gateway did not start"
    );

    let (ws, _) = connect_async(format!("ws://127.0.0.1:{WRONG_NET_PORT}"))
        .await
        .expect("ws connect");
    let (mut sink, mut stream) = ws.split();

    // Send Hello with a WRONG genesis_hash (simulate a client on a different network).
    send_req(
        &mut sink,
        &SyncRequest::Hello(Hello {
            genesis_hash: alloy_primitives::B256::repeat_byte(0xde), // wrong!
            chain_id: DEVNET_CHAIN_ID,
            tip: (0, alloy_primitives::B256::ZERO),
            validator: None,
            peer_proof: vec![],
            protocol_ver: PROTOCOL_VERSION,
        }),
    )
    .await;

    // The gateway should close the connection (Close frame or EOF, never a Hello back).
    let connection_closed = match stream.next().await {
        None => true, // EOF
        Some(Ok(Message::Close(_))) => true,
        Some(Err(_)) => true,
        Some(Ok(other)) => {
            eprintln!("unexpected frame from wrong-network gateway: {other:?}");
            false
        }
    };
    assert!(
        connection_closed,
        "gateway must close connection on wrong network (AC-F-LN4)"
    );
    println!("[wrong_network_rejected] PASS: gateway closed connection on wrong genesis_hash");
}
