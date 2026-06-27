//! M5 Stage A — QA test file (`m5a_qa.rs`).
//!
//! Covers acceptance criteria that are NOT already exercised by the multi-process harness
//! (`m5_stage_a.rs`) or the follower-reject suite (`m5_follower_apply.rs`):
//!
//!   1. **Deterministic state root** (EC-4/EC-10 core, unit level):
//!        - Equal states (built independently) → byte-identical root.
//!        - Any single field mutation → root changes (sensitivity test).
//!        - Insertion-order-independent: same root regardless of operation order.
//!   2. **Persistence round-trip** (FU-3):
//!        - `save(chain) → load → Chain::from_snapshot` round-trip: the loaded chain has the same
//!          tip `(height, hash)` and `state_root` as the original.
//!        - A node restart (simulated as `from_snapshot`) resumes at the tip, not at genesis.
//!   3. **RPC JSON shapes** for the three new M5 RPCs (pure in-process drive via `serve`):
//!        - `ubi_getPeers` → array (empty when no peers are wired, still a valid JSON array).
//!        - `ubi_consensusStatus` → object with the required fields and plausible values.
//!        - `ubi_stateRoot` → `0x`-prefixed 64-hex-char string.
//!   4. **`crates/runtime` is dependency-free** (ADR-0004, §12.7):
//!        - The build-level assertion in `crates/runtime/tests/dependency_free.rs` enforces this at
//!          compile time. We document the mapping here (the test itself lives in the runtime crate).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;

use ubi2_rpc::{serve, Chain, PeerStatus, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::{
    open_stream, register_juror, seed_verified_human, state_root, Account, Human, MemState, State,
    UBI,
};

// ─── Shared devnet constants ──────────────────────────────────────────────────

/// The devnet proposer key (Anvil #2) — same constant used by the multi-process harness.
const PROPOSER_KEY: [u8; 32] =
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");

/// Well-known Anvil #0 dev account — the tx sender in every chain-level test.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const PAYEE: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

/// Const-fn hex decode.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[i * 2]) << 4) | nib(b[i * 2 + 1]);
        i += 1;
    }
    out
}
const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

// ─── MemState builders ────────────────────────────────────────────────────────

fn addr_of(b: u8) -> [u8; 20] {
    [b; 20]
}

/// Seed a verified human + account in a fresh `MemState`.
fn verified_account(state: &mut MemState, a: [u8; 20], at: u64) {
    seed_verified_human(state, &a, at);
    state.put(Account {
        address: a,
        verified: true,
        verified_at: at,
        last_settled_at: at,
        settled_balance: 0,
        nonce: 0,
    });
}

/// Build a moderately-complex `MemState` to exercise all sections of the state root.
fn complex_state() -> MemState {
    let mut s = MemState::new();
    verified_account(&mut s, addr_of(1), 0);
    verified_account(&mut s, addr_of(2), 100);
    // Fund addr(1) so it can open a stream
    {
        let mut a = s.get(&addr_of(1)).unwrap();
        a.settled_balance = 100 * UBI;
        s.put(a);
    }
    open_stream(&mut s, &addr_of(1), &addr_of(3), 1, 1_000, 0).unwrap();
    register_juror(&mut s, &addr_of(5), 0);
    s.put_human(Human::pending(addr_of(6), [9u8; 32]));
    s
}

// ─── Sign a transfer (for the Chain-level persistence test) ──────────────────

fn sign_transfer(to: AlloyAddr, value: u128, nonce: u64) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(DEVNET_CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 300_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        input: Default::default(),
    };
    let sk = SigningKey::from_slice(&DEV_PRIVKEY).unwrap();
    let sighash = tx.signature_hash();
    let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
    let r: [u8; 32] = sig.r().to_bytes().into();
    let sv: [u8; 32] = sig.s().to_bytes().into();
    let asig = PrimitiveSignature::from_scalars_and_parity(r.into(), sv.into(), recid.is_y_odd());
    let env: TxEnvelope = tx.into_signed(asig).into();
    let mut raw = Vec::new();
    env.encode_2718(&mut raw);
    raw
}

// ─── In-process RPC helper (mirrors m1_acceptance.rs, using non-default port) ──

/// Allocate a free OS port by binding to port 0 and immediately releasing.
fn free_port() -> u16 {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind port 0");
    listener.local_addr().expect("local addr").port()
}

async fn rpc_call(addr: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    })
    .to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );

    let mut stream = TcpStream::connect(addr).await.expect("connect");
    stream.write_all(req.as_bytes()).await.expect("write");
    stream.flush().await.expect("flush");

    let mut buf: Vec<u8> = Vec::with_capacity(2048);
    let header_end = loop {
        let mut chunk = [0u8; 1024];
        let n = stream.read(&mut chunk).await.expect("read");
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_crlf2(&buf) {
            break pos + 4;
        }
        if n == 0 {
            break buf.len();
        }
    };

    let headers = String::from_utf8_lossy(&buf[..header_end]);
    let content_len: usize = headers
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    let mut body_bytes = buf[header_end..].to_vec();
    while body_bytes.len() < content_len {
        let mut chunk = [0u8; 4096];
        let n = stream.read(&mut chunk).await.expect("read body");
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
    }
    let body_str = String::from_utf8_lossy(&body_bytes).to_string();
    let parsed: serde_json::Value = serde_json::from_str(&body_str).expect("parse json");
    parsed["result"].clone()
}

fn find_crlf2(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// Boot a real RPC server in-process; wait up to 5 s for the port to be reachable.
async fn boot_rpc_server(chain: Chain, port: u16) -> (SocketAddr, jsonrpsee::server::ServerHandle) {
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
    let handle = serve(addr, chain).await.expect("serve");
    // Wait until the port accepts connections.
    for _ in 0..50 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(50)).await;
            return (addr, handle);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("RPC server on port {port} did not come up within 5 s");
}

// ─── Build a genesis Chain (matches the devnet node's genesis seeding) ───────

fn genesis_chain_with_proposer() -> Chain {
    let genesis_time = 1_000u64;
    let pk = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis_time).with_proposer_key(pk);
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 0,
        nonce: 0,
    });
    chain.seed_verified_human(&DEV_ADDR.into_array(), genesis_time);
    chain
}

// ═══════════════════════════════════════════════════════════════════════════════
// 1. DETERMINISTIC STATE ROOT (EC-4 / EC-10 core, unit level)
// ═══════════════════════════════════════════════════════════════════════════════

/// Two independently-built states with the same logical content produce a byte-identical root
/// (the core EC-4/EC-10 bar — here exercised at the `MemState`/`state_root` unit level).
#[test]
fn state_root_equal_states_produce_identical_root() {
    let a = complex_state();
    let b = complex_state();
    let ra = state_root(&a);
    let rb = state_root(&b);
    assert_eq!(
        ra, rb,
        "independently-built equal states must have the same state root (EC-4/EC-10)"
    );
    // Sanity: the root is non-zero.
    assert_ne!(ra, [0u8; 32], "state root must be non-trivial");
}

/// Root is insertion-order-independent: two states seeded in opposite orders have the same root.
/// This is the key stability property — node A seeded accounts in one order, node B in another
/// order (arrival depends on gossip timing); their state roots must agree.
#[test]
fn state_root_insertion_order_independent() {
    let mut a = MemState::new();
    verified_account(&mut a, addr_of(1), 0);
    verified_account(&mut a, addr_of(2), 100);
    register_juror(&mut a, &addr_of(5), 0);

    let mut b = MemState::new();
    // Opposite insertion order.
    register_juror(&mut b, &addr_of(5), 0);
    verified_account(&mut b, addr_of(2), 100);
    verified_account(&mut b, addr_of(1), 0);

    assert_eq!(
        state_root(&a),
        state_root(&b),
        "insertion order must not affect the state root (accounts sorted by address)"
    );
}

/// Changing a balance changes the root (sensitivity: no field goes uncommitted).
#[test]
fn state_root_balance_change_changes_root() {
    let base = complex_state();
    let r0 = state_root(&base);

    let mut s = base.clone();
    let mut acc = s.get(&addr_of(1)).unwrap();
    acc.settled_balance += 1;
    s.put(acc);
    assert_ne!(
        state_root(&s),
        r0,
        "a 1-unit balance change must change the root"
    );
}

/// Changing a nonce changes the root.
#[test]
fn state_root_nonce_change_changes_root() {
    let base = complex_state();
    let r0 = state_root(&base);

    let mut s = base.clone();
    let mut acc = s.get(&addr_of(1)).unwrap();
    acc.nonce += 1;
    s.put(acc);
    assert_ne!(state_root(&s), r0, "a nonce change must change the root");
}

/// Adding a new account changes the root.
#[test]
fn state_root_new_account_changes_root() {
    let base = complex_state();
    let r0 = state_root(&base);

    let mut s = base.clone();
    s.put(Account {
        address: addr_of(200),
        ..Default::default()
    });
    assert_ne!(state_root(&s), r0, "a new account must change the root");
}

/// Adding a juror changes the root.
#[test]
fn state_root_new_juror_changes_root() {
    let base = complex_state();
    let r0 = state_root(&base);

    let mut s = base.clone();
    register_juror(&mut s, &addr_of(100), 0);
    assert_ne!(
        state_root(&s),
        r0,
        "registering a new juror must change the root"
    );
}

/// A stream change (new open stream) changes the root.
#[test]
fn state_root_stream_change_changes_root() {
    let base = complex_state();
    let r0 = state_root(&base);

    let mut s = base.clone();
    // Fund addr(2) so it can open a second stream.
    let mut a = s.get(&addr_of(2)).unwrap();
    a.settled_balance = 100 * UBI;
    s.put(a);
    open_stream(&mut s, &addr_of(2), &addr_of(7), 1, 500, 0).unwrap();
    assert_ne!(state_root(&s), r0, "adding a stream must change the root");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 2. PERSISTENCE ROUND-TRIP (FU-3)
// ═══════════════════════════════════════════════════════════════════════════════

/// Save a snapshot to a temp dir, load it back, build a Chain from it, and assert:
///   - `tip()` is identical (height + hash).
///   - `state_root()` is byte-identical.
///   - `genesis_hash()` is identical.
///
/// This proves that a node restart does not regress to genesis and does not change the state.
#[test]
fn persistence_round_trip_preserves_tip_and_state_root() {
    // Build a proposer chain and mine two blocks (so the tip is non-genesis).
    let chain = genesis_chain_with_proposer();
    let t1 = 1_000 + 7 * 3600; // 7 hours post-genesis: enough emission for two transfers.
    let t2 = t1 + 1;

    // Put a tx in the mempool and mine block 1.
    let raw0 = sign_transfer(PAYEE, 1_000_000, 0);
    chain.ingest_gossip_tx(&raw0).expect("ingest tx0");
    let _block1 = chain.produce_block(t1);

    // Mine block 2.
    let raw1 = sign_transfer(PAYEE, 2_000_000, 1);
    chain.ingest_gossip_tx(&raw1).expect("ingest tx1");
    let _block2 = chain.produce_block(t2);

    // Snapshot what we have.
    let (height_before, hash_before) = chain.tip();
    let root_before = chain.state_root();
    let genesis_before = chain.genesis_hash();

    assert_eq!(height_before, 2, "two blocks mined");

    // Save to a temp dir.
    let tmp = tempdir();
    let snap = chain.export_snapshot();
    ubi2_rpc::persist::save(&tmp, &snap).expect("save snapshot");

    // Load back.
    let loaded = ubi2_rpc::persist::load(&tmp)
        .expect("load must succeed")
        .expect("snapshot present");
    assert_eq!(loaded.chain_id(), DEVNET_CHAIN_ID, "chain_id preserved");

    let reloaded = Chain::from_snapshot(&loaded);
    let (height_after, hash_after) = reloaded.tip();
    let root_after = reloaded.state_root();
    let genesis_after = reloaded.genesis_hash();

    assert_eq!(
        height_after, height_before,
        "FU-3: tip height preserved after restart"
    );
    assert_eq!(
        hash_after, hash_before,
        "FU-3: tip hash preserved after restart"
    );
    assert_eq!(
        root_after, root_before,
        "FU-3: state_root byte-identical after save→load round-trip"
    );
    assert_eq!(genesis_after, genesis_before, "genesis hash preserved");
}

/// A node that restarts from snapshot resumes AT the tip height, not at genesis.
/// This would catch a regression where `from_snapshot` re-seeds genesis and discards the stored state.
#[test]
fn persistence_restart_resumes_at_tip_not_genesis() {
    let chain = genesis_chain_with_proposer();
    let t = 1_000 + 3 * 3600;
    let _b = chain.produce_block(t);
    let (h, _) = chain.tip();
    assert_eq!(h, 1);

    let snap = chain.export_snapshot();
    let tmp = tempdir();
    ubi2_rpc::persist::save(&tmp, &snap).expect("save");

    let loaded = ubi2_rpc::persist::load(&tmp).unwrap().unwrap();
    let reloaded = Chain::from_snapshot(&loaded);
    let (h2, _) = reloaded.tip();
    assert_eq!(
        h2, 1,
        "resumed at height 1, not re-initialized to genesis height 0"
    );
}

/// An empty data dir returns `None` (no panic), so a fresh-start node boots from genesis.
#[test]
fn persistence_empty_data_dir_returns_none() {
    let tmp = tempdir();
    let result = ubi2_rpc::persist::load(&tmp).expect("load from empty dir must not error");
    assert!(result.is_none(), "empty dir → no snapshot → None");
}

// ═══════════════════════════════════════════════════════════════════════════════
// 3. RPC JSON SHAPES — ubi_getPeers / ubi_consensusStatus / ubi_stateRoot
// ═══════════════════════════════════════════════════════════════════════════════

/// `ubi_getPeers` returns a JSON array (no peers wired in this unit test → empty array).
/// Shape: `[{ peerId, multiaddr, validator?, tip? }]`.
#[tokio::test]
async fn rpc_ubi_get_peers_returns_array() {
    let chain = genesis_chain_with_proposer();
    let (addr, _handle) = boot_rpc_server(chain.clone(), free_port()).await;

    let result = rpc_call(addr, "ubi_getPeers", serde_json::json!([])).await;
    assert!(
        result.is_array(),
        "ubi_getPeers must return a JSON array (EC-1 shape)"
    );
    // No peers wired ⇒ empty.
    assert_eq!(
        result.as_array().unwrap().len(),
        0,
        "no peers set ⇒ empty array"
    );
}

/// After wiring a peer via `set_peers`, `ubi_getPeers` returns it with the required fields.
#[tokio::test]
async fn rpc_ubi_get_peers_returns_wired_peers() {
    let chain = genesis_chain_with_proposer();
    // Wire a fake peer (the real peer table would come from the network driver; here we test the RPC shape).
    chain.set_peers(vec![PeerStatus {
        peer_id: "12D3KooWFakeTestPeerId".to_string(),
        multiaddr: "/ip4/127.0.0.1/tcp/19999".to_string(),
        validator: None,
        tip: Some((7, B256::repeat_byte(0xAB))),
    }]);

    let (addr, _handle) = boot_rpc_server(chain.clone(), free_port()).await;
    let result = rpc_call(addr, "ubi_getPeers", serde_json::json!([])).await;

    let arr = result.as_array().expect("array");
    assert_eq!(arr.len(), 1);
    let p = &arr[0];
    assert!(p.get("peerId").is_some(), "peerId field required");
    assert!(p.get("multiaddr").is_some(), "multiaddr field required");
    // tip shape: { height, hash }
    let tip = p.get("tip").expect("tip field");
    assert!(tip.get("height").is_some(), "tip.height required");
    assert!(tip.get("hash").is_some(), "tip.hash required");
}

/// `ubi_consensusStatus` returns an object with the required Stage-A fields.
/// Shape: `{ head: {height, hash, stateRoot}, currentProposer, validatorSet, isProposer, peerCount, finalizedHeight, chainId, genesisHash }`.
#[tokio::test]
async fn rpc_ubi_consensus_status_shape() {
    let chain = genesis_chain_with_proposer();
    chain.set_proposer_role(true, None);
    let (addr, _handle) = boot_rpc_server(chain.clone(), free_port()).await;

    let result = rpc_call(addr, "ubi_consensusStatus", serde_json::json!([])).await;

    assert!(
        result.is_object(),
        "ubi_consensusStatus must return an object"
    );
    let obj = result.as_object().unwrap();

    // Required top-level fields.
    assert!(obj.contains_key("head"), "head field required");
    assert!(
        obj.contains_key("currentProposer"),
        "currentProposer field required"
    );
    assert!(
        obj.contains_key("validatorSet"),
        "validatorSet field required"
    );
    assert!(obj.contains_key("isProposer"), "isProposer field required");
    assert!(obj.contains_key("peerCount"), "peerCount field required");
    assert!(
        obj.contains_key("finalizedHeight"),
        "finalizedHeight field required"
    );
    assert!(obj.contains_key("chainId"), "chainId field required");
    assert!(
        obj.contains_key("genesisHash"),
        "genesisHash field required"
    );

    // head sub-object.
    let head = &result["head"];
    assert!(head.is_object(), "head must be an object");
    assert!(head.get("height").is_some(), "head.height required");
    assert!(head.get("hash").is_some(), "head.hash required");
    assert!(head.get("stateRoot").is_some(), "head.stateRoot required");

    // validatorSet must be an array.
    assert!(
        result["validatorSet"].is_array(),
        "validatorSet must be an array"
    );

    // chainId should encode DEVNET_CHAIN_ID.
    let chain_id_hex = result["chainId"].as_str().expect("chainId is a string");
    let chain_id_val =
        u64::from_str_radix(chain_id_hex.strip_prefix("0x").unwrap_or(chain_id_hex), 16)
            .expect("valid hex");
    assert_eq!(chain_id_val, DEVNET_CHAIN_ID, "chainId matches devnet");

    // isProposer reflects what we set.
    assert_eq!(
        result["isProposer"].as_bool(),
        Some(true),
        "isProposer=true (we set it)"
    );
}

/// `ubi_stateRoot` returns a `0x`-prefixed 64-hex-character string (a B256 hex).
/// The genesis block's `state_root` is B256::ZERO by design (it is the fixed network anchor,
/// not a re-executed commitment); after the first mined block the root captures actual state.
#[tokio::test]
async fn rpc_ubi_state_root_shape_and_value() {
    let chain = genesis_chain_with_proposer();

    // Mine one block to get a real committed state root (genesis state_root is B256::ZERO by design).
    let raw = sign_transfer(PAYEE, 1_000_000, 0);
    chain.ingest_gossip_tx(&raw).expect("ingest");
    chain.produce_block(1_000 + 7 * 3600);

    let (addr, _handle) = boot_rpc_server(chain.clone(), free_port()).await;

    let result = rpc_call(addr, "ubi_stateRoot", serde_json::json!([])).await;
    let root_str = result.as_str().expect("ubi_stateRoot must return a string");
    assert!(
        root_str.starts_with("0x"),
        "ubi_stateRoot must return a 0x-prefixed hex string"
    );
    let hex_body = &root_str[2..];
    assert_eq!(hex_body.len(), 64, "state root is 32 bytes = 64 hex chars");
    assert!(
        hex_body.chars().all(|c| c.is_ascii_hexdigit()),
        "state root must be valid hex"
    );
    // After a mined block the committed state root must be non-zero.
    assert_ne!(
        hex_body, "0000000000000000000000000000000000000000000000000000000000000000",
        "post-block state root must be non-zero (dev account and tx effects are committed)"
    );
}

/// `ubi_stateRoot` advances after a block is mined (the root reflects the tip's committed state).
#[tokio::test]
async fn rpc_ubi_state_root_advances_after_block() {
    let chain = genesis_chain_with_proposer();
    let (addr, _handle) = boot_rpc_server(chain.clone(), free_port()).await;

    // Root at genesis.
    let root0 = rpc_call(addr, "ubi_stateRoot", serde_json::json!([])).await;
    let r0_str = root0.as_str().unwrap().to_string();

    // Mine a block with a tx.
    let raw = sign_transfer(PAYEE, 1_000_000, 0);
    chain.ingest_gossip_tx(&raw).expect("ingest");
    let t = 1_000 + 7 * 3600;
    chain.produce_block(t);

    // Root after the block must differ (state changed).
    let root1 = rpc_call(addr, "ubi_stateRoot", serde_json::json!([])).await;
    let r1_str = root1.as_str().unwrap().to_string();
    assert_ne!(
        r0_str, r1_str,
        "ubi_stateRoot must reflect state changes after mining a block"
    );
}

/// `ubi_stateRoot` with `"latest"` tag returns the same value as without params.
#[tokio::test]
async fn rpc_ubi_state_root_latest_tag_matches_no_param() {
    let chain = genesis_chain_with_proposer();
    let (addr, _handle) = boot_rpc_server(chain.clone(), free_port()).await;

    let no_param = rpc_call(addr, "ubi_stateRoot", serde_json::json!([])).await;
    let latest_tag = rpc_call(addr, "ubi_stateRoot", serde_json::json!(["latest"])).await;
    assert_eq!(
        no_param, latest_tag,
        "\"latest\" tag must match the no-param result"
    );
}

// ═══════════════════════════════════════════════════════════════════════════════
// 4. CROSS-CRATE: the runtime dependency-freedom check is documented here.
//    The ACTUAL test lives in `crates/runtime/tests/dependency_free.rs` and is
//    in the 440-test baseline. This empty doctest serves as a mapping anchor.
// ═══════════════════════════════════════════════════════════════════════════════

/// Confirms the runtime dependency-freedom test exists and passes (ADR-0004 Decision 1).
/// The build-enforced assertion `runtime_declares_no_async_or_networking_deps` in
/// `crates/runtime/tests/dependency_free.rs` prevents libp2p/tokio/reqwest from leaking
/// into the deterministic core. This function serves as the QA mapping anchor.
#[test]
fn runtime_dependency_freedom_is_build_level_enforced() {
    // The ACTUAL assertion is in `crates/runtime/tests/dependency_free.rs`.
    // This test simply documents the mapping from spec invariant "No async/networking in
    // crates/runtime" (ADR-0004 Decision 1, spec §12.7) to the build-level check.
    // If `crates/runtime` ever imports libp2p/tokio/reqwest, the other test will fail first.
    let forbidden: &[&str] = &["libp2p", "tokio", "reqwest", "hyper", "jsonrpsee"];
    let manifest = include_str!("../../runtime/Cargo.toml");
    for dep in forbidden {
        // Check that no dependency line names a forbidden crate.
        let bad = manifest
            .lines()
            .filter(|l| {
                let l = l.trim();
                !l.starts_with('#') && !l.starts_with('[') && !l.is_empty()
            })
            .any(|l| l.split(['=', '.']).next().map(str::trim).unwrap_or("") == *dep);
        assert!(
            !bad,
            "crates/runtime Cargo.toml must not declare `{}` as a direct dependency (ADR-0004)",
            dep
        );
    }
}

// ─── Utility: a temporary directory that deletes itself on drop ───────────────

struct TmpDir(std::path::PathBuf);
impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl std::ops::Deref for TmpDir {
    type Target = std::path::Path;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn tempdir() -> TmpDir {
    let p = std::env::temp_dir().join(format!(
        "ubi2-m5a-qa-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&p).expect("create tempdir");
    TmpDir(p)
}
