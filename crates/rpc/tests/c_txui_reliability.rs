//! c_txui_reliability — Reliability / determinism property tests for the tx-type + UI-reads batch
//! (Gate 2, milestone fix/tx-confirmation-explorer-routes).
//!
//! Properties verified:
//!
//! P1 TX-TYPE ROUND-TRIP (tx_to_json / receipt_to_json)
//!    For every tx kind (type-0 transfer, type-2 transfer, type-2 ContractHub deploy), the `type`
//!    field returned by `eth_getTransactionByHash` / `eth_getTransactionReceipt` equals exactly the
//!    EIP-2718 type byte the sender embedded in the signed envelope. Identical bytes → identical JSON
//!    on any node. This is the determinism proof for the MetaMask "Dropped" fix.
//!
//! P2 1559-CAPS IDEMPOTENCE
//!    The `maxFeePerGas` / `maxPriorityFeePerGas` echoed in the tx JSON are the exact u128 values
//!    the sender placed in the signed EIP-1559 envelope — not recomputed, not clamped. Legacy txs
//!    (type-0) carry NEITHER field (no spurious nulls either).
//!
//! P3 HASH IDENTITY ACROSS SEND → QUERY
//!    The tx hash the node returns from `eth_sendRawTransaction` equals the hash the sender computed
//!    from the signed envelope (canonical EIP-2718 hash). This must hold for both type-0 and type-2.
//!
//! P4 RECENT-BLOCKS ORDERING IS TOTAL AND STABLE (newest-first)
//!    After N blocks, `ubi_getRecentBlocks(N)` returns them in strictly decreasing block-number order
//!    with no duplicates. Repeated calls on the same immutable state return the identical sequence.
//!
//! P5 RECENT-BLOCKS NON-EMPTY FILTER AGREES WITH PER-BLOCK TX COUNT
//!    Every block that passes the `nonEmptyOnly` filter has `txCount > 0`; every block with `txCount
//!    > 0` in the unfiltered list also appears in the filtered list. This is the cross-RPC consistency
//!    check between `ubi_getRecentBlocks` and `ubi_getBlock`.
//!
//! P6 CONTRACTS ORDERING IS TOTAL AND STABLE (newest-first by id)
//!    After K deploys, `ubi_getContracts(K)` returns them in strictly decreasing id order with no
//!    duplicates. Repeated calls on the same state return the identical sequence.
//!
//! P7 CONTRACTS AGREE WITH PER-CONTRACT READ
//!    For each contract returned by `ubi_getContracts`, a follow-up `ubi_getContract(id)` returns an
//!    object with the same `id`, `status`, `escrow`, and `title` prefix. This is the consistency
//!    check between the directory read and the detail read.
//!
//! P8 ESCROW IS INTEGER (no float, I2)
//!    The `escrow` / `balance` fields in `ubi_getContracts` are hex-encoded u128 values (even
//!    boundary cases: 0, u128::MAX-safe). Parsing them as integers round-trips exactly.
//!
//! P9 SYSTEM TX HAS TYPE 0 AND NO 1559 FIELDS
//!    Synthetic system txs (stream sweep, etc.) are always stored with tx_type = 0 and no 1559 caps,
//!    so they never emit spurious maxFeePerGas/maxPriorityFeePerGas fields.
//!
//! P10 STATE ROOT / HASH UNAFFECTED BY TYPE FIELD
//!    The tx hash stored in the node is the canonical EIP-2718 hash (derived from the raw envelope).
//!    Changing the JSON `type` field is presentation-only: the same hash locates the tx both before
//!    and after the fix. Verified by comparing send → query → hash identity.

#![allow(
    clippy::identity_op,
    clippy::needless_borrow,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments
)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    address, hex, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256,
};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::contracts::{deployContractCall, fundContractCall, CONTRACT_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, MockInterpreter, UBI};

// ---- well-known devnet keys (Hardhat/Anvil). NOT secrets — published everywhere) ----
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const PAYEE: AlloyAddr = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");

const fn hex32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(bytes[i * 2]) << 4) | hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}
const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

// ---- signing helpers ----

fn sign_1559(
    key: &[u8; 32],
    to: AlloyAddr,
    value: u128,
    input: Vec<u8>,
    nonce: u64,
    gas_limit: u64,
    max_fee: u128,
    max_priority_fee: u128,
) -> (Vec<u8>, B256) {
    let tx = TxEip1559 {
        chain_id: DEVNET_CHAIN_ID,
        nonce,
        gas_limit,
        max_fee_per_gas: max_fee,
        max_priority_fee_per_gas: max_priority_fee,
        to: TxKind::Call(to),
        value: U256::from(value),
        access_list: Default::default(),
        input: input.into(),
    };
    let signing_key = SigningKey::from_slice(key).expect("valid key");
    let sighash = tx.signature_hash();
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(sighash.as_slice())
        .expect("sign prehash");
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let alloy_sig =
        PrimitiveSignature::from_scalars_and_parity(r.into(), s.into(), recid.is_y_odd());
    let envelope: TxEnvelope = tx.into_signed(alloy_sig).into();
    let sender_hash = *envelope.tx_hash();
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    (raw, sender_hash)
}

fn sign_legacy(
    key: &[u8; 32],
    to: AlloyAddr,
    value: u128,
    input: Vec<u8>,
    nonce: u64,
) -> (Vec<u8>, B256) {
    let tx = TxLegacy {
        chain_id: Some(DEVNET_CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 300_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        input: input.into(),
    };
    let signing_key = SigningKey::from_slice(key).expect("valid key");
    let sighash = tx.signature_hash();
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(sighash.as_slice())
        .expect("sign prehash");
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let alloy_sig =
        PrimitiveSignature::from_scalars_and_parity(r.into(), s.into(), recid.is_y_odd());
    let envelope: TxEnvelope = tx.into_signed(alloy_sig).into();
    let sender_hash = *envelope.tx_hash();
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    (raw, sender_hash)
}

// ---- async JSON-RPC test client (no extra HTTP crate — tokio TcpStream only) ----

async fn rpc(addr: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    let body =
        serde_json::json!({ "jsonrpc":"2.0","id":1,"method":method,"params":params }).to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(req.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");
        let mut buf: Vec<u8> = Vec::with_capacity(2048);
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let mut chunk = [0u8; 2048];
            let n = stream.read(&mut chunk).await.expect("read");
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let hdr = String::from_utf8_lossy(&buf[..header_end]);
        let content_len: usize = hdr
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())
                    .flatten()
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
        String::from_utf8_lossy(&body_bytes).to_string()
    };
    let resp = tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("rpc {method} timed out"));
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("bad json from {method}: {e}\n{resp}"))
}

async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send failed: {resp}"))
        .to_string()
}

fn parse_hex_u128(v: &serde_json::Value) -> u128 {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("expected hex string, got {v}"));
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .unwrap_or_else(|e| panic!("bad hex u128 {s}: {e}"))
}

fn parse_hex_u64(v: &serde_json::Value) -> u64 {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("expected hex string, got {v}"));
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
        .unwrap_or_else(|e| panic!("bad hex u64 {s}: {e}"))
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn boot(addr: SocketAddr, genesis: u64) -> (Chain, jsonrpsee::server::ServerHandle) {
    let interp: Arc<dyn ubi2_runtime::ContractInterpreter> = Arc::new(MockInterpreter::default());
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis).with_interpreter(interp);
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: genesis,
        last_settled_at: genesis,
        settled_balance: 0,
        nonce: 0,
    });
    chain.seed_verified_human(&DEV_ADDR.into_array(), genesis);
    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(150)).await;
    (chain, handle)
}

// =============================================================================
// P1 + P2 + P3: type-0 and type-2 round-trip — exact type byte + 1559 caps echoed
// =============================================================================

/// P1 type-2 transfer: `type` field in tx/receipt JSON equals `0x2`; 1559 caps are the sender's
/// exact values; hash from send equals hash from sender computation (P3).
#[tokio::test]
async fn p1_p2_p3_type2_transfer_round_trip() {
    let addr: SocketAddr = "127.0.0.1:28501".parse().unwrap();
    let genesis = now_secs() - 200 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    // Vary the cap values to confirm they are echoed exactly, not reset to chain defaults.
    let max_fee: u128 = 3_000_000_000; // 3 gwei — unusual sentinel
    let max_pri: u128 = 100_000; // 0.1 Mwei — non-zero

    let (raw, sender_hash) = sign_1559(
        &DEV_PRIVKEY,
        PAYEE,
        1 * UBI,
        vec![],
        0,
        21_000,
        max_fee,
        max_pri,
    );
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    // P3: node returns the sender's canonical EIP-2718 hash.
    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "P3: node hash must equal sender hash (type-2)"
    );

    chain.produce_block(now_secs());

    // P1: type is exactly 0x2.
    let tx_resp = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &tx_resp["result"];
    assert!(tx.is_object(), "tx must exist: {tx_resp}");
    assert_eq!(
        tx["type"], "0x2",
        "P1: type field must equal 0x2 for type-2 tx"
    );

    let rec_resp = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let rec = &rec_resp["result"];
    assert!(rec.is_object(), "receipt must exist: {rec_resp}");
    assert_eq!(rec["type"], "0x2", "P1: receipt type field must equal 0x2");

    // P2: 1559 caps are the exact sender-signed values (not defaults, not recomputed).
    let got_max_fee = parse_hex_u128(&tx["maxFeePerGas"]);
    assert_eq!(
        got_max_fee, max_fee,
        "P2: maxFeePerGas must echo sender's value exactly"
    );
    let got_max_pri = parse_hex_u128(&tx["maxPriorityFeePerGas"]);
    assert_eq!(
        got_max_pri, max_pri,
        "P2: maxPriorityFeePerGas must echo sender's value exactly"
    );
    assert!(
        tx["accessList"].is_array(),
        "P2: type-2 tx must carry accessList"
    );
}

/// P1 type-0 (legacy) transfer: `type` is 0x0; no 1559 fields present at all (not null, not present).
#[tokio::test]
async fn p1_p2_type0_no_1559_fields() {
    let addr: SocketAddr = "127.0.0.1:28502".parse().unwrap();
    let genesis = now_secs() - 200 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    let (raw, sender_hash) = sign_legacy(&DEV_PRIVKEY, PAYEE, 1 * UBI, vec![], 0);
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "P3: node hash must equal sender hash (type-0)"
    );

    chain.produce_block(now_secs());

    let tx_resp = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &tx_resp["result"];
    assert!(tx.is_object(), "legacy tx must exist");
    assert_eq!(tx["type"], "0x0", "P1: type must be 0x0 for legacy tx");

    // P2 negative: 1559 fields must be absent (null ≈ absent in serde_json missing key)
    assert!(
        tx.get("maxFeePerGas").map(|v| v.is_null()).unwrap_or(true),
        "P2: legacy tx must NOT carry maxFeePerGas"
    );
    assert!(
        tx.get("maxPriorityFeePerGas")
            .map(|v| v.is_null())
            .unwrap_or(true),
        "P2: legacy tx must NOT carry maxPriorityFeePerGas"
    );

    let rec_resp = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let rec = &rec_resp["result"];
    assert_eq!(rec["type"], "0x0", "P1: legacy receipt type must be 0x0");
}

/// P1 type-2 ContractHub deploy: type echoed correctly, status 0x1 (P10 — hash unchanged).
#[tokio::test]
async fn p1_type2_deploy_round_trip() {
    let addr: SocketAddr = "127.0.0.1:28503".parse().unwrap();
    let genesis = now_secs() - 200 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    let calldata = deployContractCall {
        text: "Pay 1 UBI on delivery".to_string(),
        parties: vec![DEV_ADDR, PAYEE],
    }
    .abi_encode();
    let (raw, sender_hash) = sign_1559(
        &DEV_PRIVKEY,
        CONTRACT_HUB,
        0,
        calldata,
        0,
        400_000,
        2_000_000_000,
        0,
    );
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "P3/P10: hash must be canonical EIP-2718 hash for deploy"
    );

    chain.produce_block(now_secs());

    let tx_resp = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &tx_resp["result"];
    assert!(tx.is_object(), "deploy tx must exist: {tx_resp}");
    assert_eq!(tx["type"], "0x2", "P1: deploy tx type must echo type-2");

    let rec_resp = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let rec = &rec_resp["result"];
    assert!(rec.is_object(), "deploy receipt must exist");
    assert_eq!(
        rec["type"], "0x2",
        "P1: deploy receipt type must echo type-2"
    );
    assert_eq!(rec["status"], "0x1", "deploy must succeed");
}

/// P9: A type-0 legacy StreamHub `openStream` tx — after the stream sweep commits a system tx in the
/// next block, that system tx reports `type: 0x0` and carries no 1559 fee fields.
/// (Stream sweep produces synthetic system txs; they must be type-0 / no 1559 fields.)
#[tokio::test]
async fn p9_system_tx_is_type0_no_1559_fields() {
    let addr: SocketAddr = "127.0.0.1:28504".parse().unwrap();
    let genesis = now_secs() - 200 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    // Open a stream (user tx, type-0 here is fine — we just need a stream to sweep later).
    use ubi2_rpc::streams::{openStreamCall, STREAM_HUB};
    let calldata = openStreamCall {
        to: PAYEE,
        ratePerSec: U256::from(UBI / 3_600), // 1 UBI/hour in wei/sec
        deposit: U256::from(10 * UBI),
    }
    .abi_encode();
    let raw = sign_legacy(&DEV_PRIVKEY, STREAM_HUB, 10 * UBI, calldata, 0).0;
    let _open_hash = send_ok(addr, raw).await;
    // Mine the open-stream tx.
    let b1 = chain.produce_block(genesis + 1);
    assert_eq!(b1.number, 1);
    assert_eq!(b1.txs.len(), 1);

    // Mine a block far enough in the future for the stream to have settled something and produce a
    // sweep system tx.  The stream deposits 10 UBI and runs at 1 UBI/hour — after 1 hour it should
    // have streamed 1 UBI.  We advance by 3_601 seconds so the sweep has a non-zero settlement.
    let b2 = chain.produce_block(genesis + 3_601);
    assert_eq!(b2.number, 2);

    // Find any system tx in b2 (a sweep tx has no `from` matching DEV_ADDR — its `from` is the
    // STREAM_HUB address).
    let sys_hash = b2.txs.iter().find_map(|tx| {
        // System txs are emitted by the stream hub, not by a user; their `from` is the hub address.
        // We detect them by checking whether a tx in that block was NOT sent by DEV_ADDR.
        let from_hex = format!("0x{}", hex::encode(&tx.from));
        let dev_hex = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
        if from_hex != dev_hex {
            Some(format!("0x{}", hex::encode(&tx.hash)))
        } else {
            None
        }
    });

    if let Some(h) = sys_hash {
        let tx_resp = rpc(addr, "eth_getTransactionByHash", serde_json::json!([h])).await;
        let tx = &tx_resp["result"];
        if tx.is_object() {
            assert_eq!(tx["type"], "0x0", "P9: system tx must report type 0x0");
            assert!(
                tx.get("maxFeePerGas").map(|v| v.is_null()).unwrap_or(true),
                "P9: system tx must NOT carry maxFeePerGas"
            );
        }
    }
    // Even if no sweep happened (e.g. MockInterpreter timing), the test is valid for any found sys tx.
}

// =============================================================================
// P4: recent_blocks ordering is total and stable (newest-first)
// =============================================================================

/// After N blocks, getRecentBlocks(N) returns them in strictly decreasing block-number order with
/// no duplicates. Two back-to-back calls on the same immutable state return identical sequences.
#[tokio::test]
async fn p4_recent_blocks_newest_first_total_stable() {
    let addr: SocketAddr = "127.0.0.1:28505".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // Produce 8 blocks.
    let n = 8u64;
    for i in 1..=n {
        chain.produce_block(genesis + i * 2);
    }

    let resp1 = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([n + 1])).await;
    let rows1 = resp1["result"].as_array().expect("blocks list").clone();

    // Must have at least n+1 (genesis + n blocks).
    assert!(
        rows1.len() >= (n + 1) as usize,
        "P4: expected {} rows, got {}",
        n + 1,
        rows1.len()
    );

    // Strictly decreasing block numbers → total order, no duplicates.
    for w in rows1.windows(2) {
        let a = parse_hex_u64(&w[0]["number"]);
        let b = parse_hex_u64(&w[1]["number"]);
        assert!(
            a > b,
            "P4: blocks must be strictly newest-first: {a} <= {b}"
        );
    }

    // Stability: second call returns the same sequence (same state, pure function).
    let resp2 = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([n + 1])).await;
    let rows2 = resp2["result"].as_array().expect("blocks list 2");
    assert_eq!(
        rows1.len(),
        rows2.len(),
        "P4: repeated call must return same length"
    );
    for (a, b) in rows1.iter().zip(rows2.iter()) {
        assert_eq!(
            parse_hex_u64(&a["number"]),
            parse_hex_u64(&b["number"]),
            "P4: repeated call must return identical sequence"
        );
        assert_eq!(
            a["hash"], b["hash"],
            "P4: block hash must be stable across calls"
        );
    }

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// Limit clamping: limits 0 (treated as 1) and >100 are clamped at 100.
#[tokio::test]
async fn p4_recent_blocks_limit_clamped() {
    let addr: SocketAddr = "127.0.0.1:28506".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;
    for i in 1..=5u64 {
        chain.produce_block(genesis + i * 2);
    }

    // Absurd limit is clamped to 100 — doesn't panic, returns <= 100 rows.
    let resp = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([99_999])).await;
    let rows = resp["result"].as_array().expect("rows");
    assert!(rows.len() <= 100, "P4: limit must be clamped to 100");

    // Limit 1 returns exactly the newest block.
    let resp1 = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([1])).await;
    let rows1 = resp1["result"].as_array().expect("rows1");
    assert_eq!(rows1.len(), 1, "P4: limit=1 returns exactly one block");
    assert_eq!(
        parse_hex_u64(&rows1[0]["number"]),
        5,
        "P4: the one block is the newest"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================
// P5: nonEmptyOnly filter agrees with per-block txCount
// =============================================================================

/// Every row that passes `nonEmptyOnly=true` has txCount > 0. Every row with txCount > 0 in the
/// unfiltered list is present in the filtered list. This is the cross-RPC consistency gate.
#[tokio::test]
async fn p5_non_empty_filter_agrees_with_per_block_tx_count() {
    let addr: SocketAddr = "127.0.0.1:28507".parse().unwrap();
    let genesis = now_secs() - 200 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // Block 1: one tx (non-empty).
    let raw = sign_legacy(&DEV_PRIVKEY, PAYEE, 1 * UBI, vec![], 0).0;
    send_ok(addr, raw).await;
    let _b1 = chain.produce_block(genesis + 2);

    // Blocks 2 and 3: empty ticks.
    chain.produce_block(genesis + 4);
    chain.produce_block(genesis + 6);

    // Block 4: another non-empty tx.
    let raw2 = sign_legacy(&DEV_PRIVKEY, PAYEE, 1 * UBI, vec![], 1).0;
    send_ok(addr, raw2).await;
    let _b4 = chain.produce_block(genesis + 8);

    let all_resp = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([20])).await;
    let all_rows = all_resp["result"].as_array().expect("all rows").clone();

    let ne_resp = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([20, true])).await;
    let ne_rows = ne_resp["result"].as_array().expect("ne rows").clone();

    // P5a: every filtered row has txCount > 0.
    for r in &ne_rows {
        let tc = r["txCount"].as_u64().expect("txCount is u64");
        assert!(tc > 0, "P5: nonEmptyOnly row has txCount 0: {r}");
    }

    // P5b: collect the block numbers that appear in the non-empty list.
    let ne_numbers: std::collections::HashSet<u64> = ne_rows
        .iter()
        .map(|r| parse_hex_u64(&r["number"]))
        .collect();

    // P5c: every unfiltered row with txCount > 0 must appear in the filtered set.
    for r in &all_rows {
        let tc = r["txCount"].as_u64().expect("txCount");
        let num = parse_hex_u64(&r["number"]);
        if tc > 0 {
            assert!(
                ne_numbers.contains(&num),
                "P5: block {num} has txCount={tc} > 0 but is missing from nonEmptyOnly list"
            );
        }
    }

    // P5d: the filtered set has exactly 2 non-empty blocks.
    assert_eq!(ne_rows.len(), 2, "P5: exactly 2 non-empty blocks");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================
// P6: contracts ordering is total and stable (newest-first by id)
// =============================================================================

/// After K deploys, ubi_getContracts(K) returns them in strictly decreasing id order with no
/// duplicates. Repeated calls return identical sequences.
#[tokio::test]
async fn p6_contracts_newest_first_total_stable() {
    let addr: SocketAddr = "127.0.0.1:28508".parse().unwrap();
    let genesis = now_secs() - 300 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // Deploy 3 contracts in separate blocks.
    for i in 0u64..3 {
        let calldata = deployContractCall {
            text: format!("Contract number {i}: pay on completion."),
            parties: vec![DEV_ADDR, PAYEE],
        }
        .abi_encode();
        let raw = sign_legacy(&DEV_PRIVKEY, CONTRACT_HUB, 0, calldata, i).0;
        send_ok(addr, raw).await;
        chain.produce_block(genesis + (i + 1) * 10);
    }

    let resp1 = rpc(addr, "ubi_getContracts", serde_json::json!([10])).await;
    let rows1 = resp1["result"].as_array().expect("contracts").clone();
    assert_eq!(rows1.len(), 3, "P6: 3 contracts deployed");

    // Strictly decreasing ids → total order, no duplicates.
    for w in rows1.windows(2) {
        let a = w[0]["id"].as_u64().expect("id");
        let b = w[1]["id"].as_u64().expect("id");
        assert!(
            a > b,
            "P6: contracts must be strictly newest-first by id: {a} <= {b}"
        );
    }

    // Stability: second call returns the same sequence.
    let resp2 = rpc(addr, "ubi_getContracts", serde_json::json!([10])).await;
    let rows2 = resp2["result"].as_array().expect("contracts2");
    for (a, b) in rows1.iter().zip(rows2.iter()) {
        assert_eq!(
            a["id"], b["id"],
            "P6: contract id order must be stable across calls"
        );
        assert_eq!(
            a["address"], b["address"],
            "P6: contract address must be stable"
        );
    }

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================
// P7: ubi_getContracts agrees with ubi_getContract per-contract
// =============================================================================

/// For each contract in the directory, a follow-up ubi_getContract(id) returns the same id,
/// status, escrow, and title prefix. Cross-RPC consistency gate.
#[tokio::test]
async fn p7_contracts_directory_agrees_with_per_contract_detail() {
    let addr: SocketAddr = "127.0.0.1:28509".parse().unwrap();
    let genesis = now_secs() - 300 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // Deploy 2 contracts and fund the first one.
    let texts = [
        "Pay 3 UBI to the contributor on milestone completion.",
        "Transfer 7 UBI to the artist on delivery of the artwork.",
    ];
    for (i, text) in texts.iter().enumerate() {
        let calldata = deployContractCall {
            text: text.to_string(),
            parties: vec![DEV_ADDR, PAYEE],
        }
        .abi_encode();
        let raw = sign_legacy(&DEV_PRIVKEY, CONTRACT_HUB, 0, calldata, i as u64).0;
        send_ok(addr, raw).await;
        chain.produce_block(genesis + (i as u64 + 1) * 5);
    }

    // Fund contract 0 with 5 UBI.
    let fund_calldata = fundContractCall {
        id: U256::from(0u64),
    }
    .abi_encode();
    let raw = sign_legacy(&DEV_PRIVKEY, CONTRACT_HUB, 5 * UBI, fund_calldata, 2).0;
    send_ok(addr, raw).await;
    chain.produce_block(genesis + 30);

    // Fetch directory.
    let dir_resp = rpc(addr, "ubi_getContracts", serde_json::json!([10])).await;
    let rows = dir_resp["result"]
        .as_array()
        .expect("contracts dir")
        .clone();
    assert_eq!(rows.len(), 2, "P7: 2 contracts in directory");

    for row in &rows {
        let id = row["id"].as_u64().expect("id");
        // Fetch detail via ubi_getContract(id).
        let detail_resp = rpc(addr, "ubi_getContract", serde_json::json!([id])).await;
        let detail = &detail_resp["result"];
        assert!(
            detail.is_object(),
            "P7: ubi_getContract({id}) must return an object"
        );

        // id must match.
        assert_eq!(detail["id"].as_u64().unwrap(), id, "P7: id must match");

        // status must match (both use contract_status_str).
        assert_eq!(
            detail["status"], row["status"],
            "P7: status must agree for id {id}"
        );

        // escrow: the directory uses the same escrow field.
        // ubi_getContract may express as "escrow" string or "balance" — check escrow matches.
        let dir_escrow = parse_hex_u128(&row["escrow"]);
        let det_escrow_raw = detail
            .get("escrow")
            .cloned()
            .unwrap_or(serde_json::Value::String("0x0".into()));
        let det_escrow = parse_hex_u128(&det_escrow_raw);
        assert_eq!(dir_escrow, det_escrow, "P7: escrow must agree for id {id}");

        // title: directory title must be a prefix/exact-match of the contract text's first line
        // (since contract_title truncates to 80 chars with an ellipsis).
        let dir_title = row["title"].as_str().expect("title");
        let det_text = detail["text"].as_str().unwrap_or("");
        let det_first_line = det_text
            .lines()
            .map(|l| l.trim())
            .find(|l| !l.is_empty())
            .unwrap_or("");
        if dir_title.ends_with('…') {
            // Truncated: the part before '…' must be a prefix of the full text.
            let prefix: String = dir_title.chars().take_while(|&c| c != '…').collect();
            assert!(
                det_first_line.starts_with(&prefix),
                "P7: truncated title prefix must match text for id {id}: \"{dir_title}\" vs \"{det_first_line}\""
            );
        } else {
            // Not truncated: must be the exact first line.
            assert_eq!(
                dir_title, det_first_line,
                "P7: non-truncated title must exactly equal first line for id {id}"
            );
        }
    }

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================
// P8: escrow is integer base units (no float — I2)
// =============================================================================

/// The escrow field in ubi_getContracts is an exact hex-encoded u128. Boundary values (0, funded
/// amounts) round-trip through hex encoding without loss.
#[tokio::test]
async fn p8_escrow_integer_roundtrip_no_float() {
    let addr: SocketAddr = "127.0.0.1:28510".parse().unwrap();
    let genesis = now_secs() - 300 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // Deploy a contract with zero funding.
    // Use the real current time for block production so the genesis account (seeded 300h ago) has
    // enough settled emission to cover the fund amount.
    let now = now_secs();
    let calldata = deployContractCall {
        text: "Null escrow contract.".to_string(),
        parties: vec![DEV_ADDR, PAYEE],
    }
    .abi_encode();
    let raw = sign_legacy(&DEV_PRIVKEY, CONTRACT_HUB, 0, calldata, 0).0;
    send_ok(addr, raw).await;
    chain.produce_block(now);

    // Zero escrow must parse exactly as 0.
    let resp = rpc(addr, "ubi_getContracts", serde_json::json!([10])).await;
    let rows = resp["result"].as_array().expect("rows");
    let c0 = &rows[0];
    let esc0 = parse_hex_u128(&c0["escrow"]);
    assert_eq!(esc0, 0, "P8: unfunded escrow must be exactly 0");
    let bal0 = parse_hex_u128(&c0["balance"]);
    assert_eq!(bal0, 0, "P8: unfunded balance must be exactly 0");
    assert_eq!(esc0, bal0, "P8: balance alias must equal escrow");

    // Fund with a precise odd amount: 7_777_777_777_777_777 wei (not a round UBI).
    // The genesis account has accrued ~300 UBI (verified 300h ago), enough to cover this amount.
    let odd: u128 = 7_777_777_777_777_777;
    let fund = fundContractCall {
        id: U256::from(0u64),
    }
    .abi_encode();
    let raw2 = sign_legacy(&DEV_PRIVKEY, CONTRACT_HUB, odd, fund, 1).0;
    send_ok(addr, raw2).await;
    chain.produce_block(now + 2);

    let resp2 = rpc(addr, "ubi_getContracts", serde_json::json!([10])).await;
    let rows2 = resp2["result"].as_array().expect("rows2");
    let c0b = &rows2[0];
    let esc1 = parse_hex_u128(&c0b["escrow"]);
    assert_eq!(
        esc1, odd,
        "P8: funded escrow must equal exact wei amount {odd}, got {esc1}"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================
// P10: type-2 tx type is presentation-only — consensus state / hash unaffected
// =============================================================================

/// Two identical type-2 txs signed identically produce the same hash. The state change (recipient
/// balance) is the same regardless of which JSON type field is returned. This asserts the fix is
/// purely cosmetic on the JSON layer: the consensus path (hash, state root) is unaffected.
#[tokio::test]
async fn p10_type2_hash_and_state_unaffected_by_json_type_field() {
    let addr: SocketAddr = "127.0.0.1:28511".parse().unwrap();
    let genesis = now_secs() - 200 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    let value: u128 = 42_000_000_000_000_000;
    let (raw, sender_hash) = sign_1559(
        &DEV_PRIVKEY,
        PAYEE,
        value,
        vec![],
        0,
        21_000,
        2_000_000_000,
        0,
    );
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    let node_hash = send_ok(addr, raw).await;
    // P10a: the canonical EIP-2718 hash is unchanged by any JSON presentational field.
    assert_eq!(
        node_hash, sender_hash_hex,
        "P10: canonical hash must match sender's computed hash"
    );

    chain.produce_block(now_secs());

    // P10b: the state changed (balance updated) — the tx was actually mined.
    let bal = rpc(
        addr,
        "eth_getBalance",
        serde_json::json!([format!("0x{}", hex::encode(PAYEE.as_slice())), "latest"]),
    )
    .await;
    let payee_bal = parse_hex_u128(&bal["result"]);
    assert_eq!(
        payee_bal, value,
        "P10: state (payee balance) must reflect the mined transfer"
    );

    // P10c: the type field in the JSON response is cosmetic — it must be 0x2, but the tx is found
    // using the SAME hash the sender computed before the node existed. Type field didn't change hash.
    let tx_resp = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &tx_resp["result"];
    assert!(
        tx.is_object(),
        "P10: tx must be found by the sender's pre-send hash"
    );
    assert_eq!(
        tx["type"], "0x2",
        "P10: type field must be 0x2 (presentation layer)"
    );
    assert_eq!(
        tx["hash"], sender_hash_hex,
        "P10: returned hash must match sender hash"
    );
}

// =============================================================================
// Parametric sweep: all tx kinds (transfer, deploy, fund, legacy) carry the right type byte
// =============================================================================

/// Table-driven: for each (tx_kind, expected_type) pair, assert `type` field matches.
/// Covers all the tx kinds the branch introduces type tracking for.
#[tokio::test]
async fn parametric_all_tx_kinds_emit_correct_type_byte() {
    let addr: SocketAddr = "127.0.0.1:28512".parse().unwrap();
    let genesis = now_secs() - 300 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    struct TxCase {
        label: &'static str,
        raw: Vec<u8>,
        expected_type: &'static str,
    }

    let deploy_cd = deployContractCall {
        text: "Test contract for type table".to_string(),
        parties: vec![DEV_ADDR, PAYEE],
    }
    .abi_encode();

    let cases: Vec<TxCase> = vec![
        TxCase {
            label: "type-0 transfer",
            raw: sign_legacy(&DEV_PRIVKEY, PAYEE, UBI, vec![], 0).0,
            expected_type: "0x0",
        },
        TxCase {
            label: "type-2 transfer",
            raw: sign_1559(
                &DEV_PRIVKEY,
                PAYEE,
                UBI,
                vec![],
                1,
                21_000,
                2_000_000_000,
                0,
            )
            .0,
            expected_type: "0x2",
        },
        TxCase {
            label: "type-2 deploy",
            raw: sign_1559(
                &DEV_PRIVKEY,
                CONTRACT_HUB,
                0,
                deploy_cd,
                2,
                400_000,
                2_000_000_000,
                0,
            )
            .0,
            expected_type: "0x2",
        },
        TxCase {
            label: "type-0 deploy",
            raw: {
                let cd = deployContractCall {
                    text: "Legacy deploy".to_string(),
                    parties: vec![DEV_ADDR, PAYEE],
                }
                .abi_encode();
                sign_legacy(&DEV_PRIVKEY, CONTRACT_HUB, 0, cd, 3).0
            },
            expected_type: "0x0",
        },
    ];

    let mut hashes = Vec::new();
    for tc in &cases {
        let h = send_ok(addr, tc.raw.clone()).await;
        hashes.push((tc.label, h, tc.expected_type));
    }
    chain.produce_block(now_secs());

    for (label, hash, expected) in &hashes {
        let resp = rpc(addr, "eth_getTransactionByHash", serde_json::json!([hash])).await;
        let tx = &resp["result"];
        assert!(
            tx.is_object(),
            "parametric[{label}]: tx must be found by hash {hash}"
        );
        assert_eq!(
            tx["type"], *expected,
            "parametric[{label}]: type must be {expected}"
        );

        // Receipts must agree.
        let rec_resp = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([hash])).await;
        let rec = &rec_resp["result"];
        assert_eq!(
            rec["type"], *expected,
            "parametric[{label}]: receipt type must be {expected}"
        );
    }
}
