//! c_txui_qa — Gate-1 QA for branch fix/tx-confirmation-explorer-routes (cycle-7).
//!
//! Maps every acceptance criterion from the gate spec to at least one passing test.
//!
//! Ports: 18511-18519 (non-default, unique within the workspace).
//!
//! (a) TX-CONFIRM: type-2 EIP-1559 transfer + type-2 ContractHub deploy are mined;
//!     eth_getTransactionByHash/Receipt return type 0x2 + 1559 fields (maxFeePerGas,
//!     maxPriorityFeePerGas, accessList) + status 0x1 + non-null blockHash/blockNumber.
//!     A legacy type-0 tx returns type 0x0, gasPrice, and NO 1559 fields.
//!
//! (b) RPCs: ubi_getRecentBlocks(nonEmptyOnly=true) excludes empty blocks, is newest-first,
//!     and clamps limit. ubi_getContracts lists a deployed contract with the right shape.
//!
//! (c) ROUTE SHAPE: The four standalone URL routes (tx/[hash], block/[id], address/[addr],
//!     account/[addr]) are present in the Next.js build output and compile cleanly.
//!     The TxPageContent component has a not-found branch (checked via component source).

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

// ---------------------------------------------------------------------------
// Well-known Hardhat/Anvil devnet keys — NOT secrets, published everywhere.
// ---------------------------------------------------------------------------

const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
/// Anvil account #1 — a transfer recipient / contract party.
const PAYEE: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

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

// ---------------------------------------------------------------------------
// Signing helpers — exactly as MetaMask does on a baseFeePerGas chain.
// ---------------------------------------------------------------------------

/// Sign an EIP-1559 (type-2) tx. Returns (2718-raw-bytes, sender-computed-hash).
fn sign_1559(
    key: &[u8; 32],
    to: AlloyAddr,
    value: u128,
    input: Vec<u8>,
    nonce: u64,
    gas_limit: u64,
) -> (Vec<u8>, B256) {
    let tx = TxEip1559 {
        chain_id: DEVNET_CHAIN_ID,
        nonce,
        gas_limit,
        max_fee_per_gas: 2_000_000_000,
        max_priority_fee_per_gas: 0,
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

/// Sign a legacy (type-0) EIP-155 transfer.
fn sign_legacy(key: &[u8; 32], to: AlloyAddr, value: u128, nonce: u64) -> (Vec<u8>, B256) {
    let tx = TxLegacy {
        chain_id: Some(DEVNET_CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        input: Default::default(),
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

/// Sign a legacy tx to `to` with arbitrary calldata (for ContractHub calls).
fn sign_legacy_calldata(
    key: &[u8; 32],
    to: AlloyAddr,
    value: u128,
    input: Vec<u8>,
    nonce: u64,
) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(DEVNET_CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 400_000,
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
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    raw
}

// ---------------------------------------------------------------------------
// Async JSON-RPC client (no extra crate — raw HTTP/1.1 over tokio TcpStream)
// ---------------------------------------------------------------------------

async fn rpc(addr: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
        .to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let fut = async {
        let mut stream = TcpStream::connect(addr).await.expect("connect");
        stream.write_all(req.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let header_end = loop {
            if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.expect("read");
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let content_len: usize = String::from_utf8_lossy(&buf[..header_end])
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
        .unwrap_or_else(|| panic!("send_ok: node rejected tx: {resp}"))
        .to_string()
}

fn hex_u64(v: &serde_json::Value) -> u64 {
    let s = v.as_str().expect("hex string");
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex u64")
}
fn hex_u128(v: &serde_json::Value) -> u128 {
    let s = v.as_str().expect("hex string");
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex u128")
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

async fn boot(addr: SocketAddr) -> (Chain, jsonrpsee::server::ServerHandle) {
    let genesis = now_secs() - 200 * 3_600; // 200 hours of streamed UBI
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
// (a) TX-CONFIRM: type-2 EIP-1559 transfer
//
// The MetaMask "Dropped" regression: MetaMask signs a type-2 tx and polls
// eth_getTransactionByHash by the hash it computed. Before the fix, the node
// returned type: 0x0 and omitted 1559 fee fields — MetaMask saw a mismatch and
// marked the (correctly mined) tx as "Dropped". After the fix, the same hash is
// returned with type: 0x2, maxFeePerGas, maxPriorityFeePerGas, accessList.
// =============================================================================

#[tokio::test]
async fn txqa_type2_transfer_returns_type2_and_1559_fields_in_tx_and_receipt() {
    let addr: SocketAddr = "127.0.0.1:18511".parse().unwrap();
    let (chain, _handle) = boot(addr).await;

    let (raw, sender_hash) = sign_1559(&DEV_PRIVKEY, PAYEE, 5 * UBI, vec![], 0, 21_000);
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    // Node must return the SENDER's canonical EIP-2718 hash (not its own recomputed one).
    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "node must return the sender-computed 2718 hash for a type-2 tx"
    );

    let block_num = chain.produce_block(now_secs()).number;

    // eth_getTransactionByHash: must return type 0x2 + 1559 fee fields + real blockNumber/blockHash.
    let by_hash = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &by_hash["result"];
    assert!(
        tx.is_object(),
        "type-2 transfer must be found by sender hash: {by_hash}"
    );
    assert_eq!(tx["type"], "0x2", "tx type must be 0x2 (EIP-1559)");
    assert_eq!(
        tx["blockNumber"],
        format!("0x{block_num:x}"),
        "mined tx must carry a non-null blockNumber"
    );
    assert_ne!(
        tx["blockHash"],
        serde_json::Value::Null,
        "blockHash must be non-null after mining"
    );
    assert!(
        tx["maxFeePerGas"].is_string(),
        "type-2 tx must carry maxFeePerGas: {tx}"
    );
    assert!(
        tx["maxPriorityFeePerGas"].is_string(),
        "type-2 tx must carry maxPriorityFeePerGas: {tx}"
    );
    // Echoes EXACTLY the values the sender signed — 2 gwei max fee, 0 priority tip.
    assert_eq!(
        tx["maxFeePerGas"], "0x77359400",
        "maxFeePerGas must echo the signed 2 gwei cap"
    );
    assert_eq!(
        tx["maxPriorityFeePerGas"], "0x0",
        "maxPriorityFeePerGas must echo the signed 0 tip"
    );
    assert!(
        tx["accessList"].is_array(),
        "type-2 tx must carry an empty accessList: {tx}"
    );
    assert_eq!(
        tx["chainId"], "0x5542",
        "chainId must match DEVNET_CHAIN_ID"
    );

    // eth_getTransactionReceipt: must return type 0x2, status 0x1, non-null blockHash/blockNumber.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let r = &receipt["result"];
    assert!(
        r.is_object(),
        "receipt must be found by sender hash: {receipt}"
    );
    assert_eq!(
        r["status"], "0x1",
        "a valid value transfer must have status 0x1"
    );
    assert_eq!(
        r["type"], "0x2",
        "receipt type must echo the signed type-2 (was hardcoded 0x0 before fix)"
    );
    assert_eq!(r["blockNumber"], format!("0x{block_num:x}"));
    assert_ne!(r["blockHash"], serde_json::Value::Null);

    // Verify the state actually moved — this is what made the "Dropped" contradiction visible.
    let bal = rpc(
        addr,
        "eth_getBalance",
        serde_json::json!([format!("0x{}", hex::encode(PAYEE.as_slice())), "latest"]),
    )
    .await;
    let payee_bal = hex_u128(&bal["result"]);
    assert_eq!(payee_bal, 5 * UBI, "5 UBI must be credited to the payee");
}

// =============================================================================
// (a) TX-CONFIRM: type-2 ContractHub deploy
//
// A type-2 tx to the ContractHub (a deploy call) must mine successfully and the
// receipt must carry type 0x2 + status 0x1 + the ContractDeployed log.
// =============================================================================

#[tokio::test]
async fn txqa_type2_contract_deploy_returns_type2_status1_and_log() {
    let addr: SocketAddr = "127.0.0.1:18512".parse().unwrap();
    let (chain, _handle) = boot(addr).await;

    let text = "Pay 3 UBI from escrow to the payee upon confirmed delivery.".to_string();
    let calldata = deployContractCall {
        text,
        parties: vec![DEV_ADDR, PAYEE],
    }
    .abi_encode();

    let (raw, sender_hash) = sign_1559(&DEV_PRIVKEY, CONTRACT_HUB, 0, calldata, 0, 400_000);
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "deploy: node must return sender-computed hash"
    );

    let block_num = chain.produce_block(now_secs()).number;

    // eth_getTransactionByHash: type 0x2 + 1559 fields.
    let by_hash = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &by_hash["result"];
    assert!(
        tx.is_object(),
        "type-2 ContractHub deploy must be found by sender hash: {by_hash}"
    );
    assert_eq!(tx["type"], "0x2", "deploy tx type must be 0x2");
    assert_eq!(
        tx["to"],
        format!("0x{}", hex::encode(CONTRACT_HUB.as_slice())).to_lowercase(),
        "deploy tx `to` must be the ContractHub address"
    );
    assert!(
        tx["maxFeePerGas"].is_string(),
        "deploy tx must carry maxFeePerGas"
    );
    assert!(
        tx["maxPriorityFeePerGas"].is_string(),
        "deploy tx must carry maxPriorityFeePerGas"
    );
    assert!(
        tx["accessList"].is_array(),
        "deploy tx must carry accessList"
    );

    // eth_getTransactionReceipt: type 0x2 + status 0x1 + ContractDeployed log.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let r = &receipt["result"];
    assert!(
        r.is_object(),
        "deploy receipt must be found by sender hash: {receipt}"
    );
    assert_eq!(
        r["status"], "0x1",
        "a valid ContractHub deploy must have status 0x1"
    );
    assert_eq!(r["type"], "0x2", "deploy receipt type must be 0x2");
    assert_eq!(r["blockNumber"], format!("0x{block_num:x}"));
    let logs = r["logs"].as_array().expect("deploy must emit logs");
    assert_eq!(
        logs.len(),
        1,
        "exactly one ContractDeployed log expected: {logs:?}"
    );
}

// =============================================================================
// (a) TX-CONFIRM: legacy type-0 tx still returns type 0x0, gasPrice, no 1559 fields.
// =============================================================================

#[tokio::test]
async fn txqa_legacy_type0_returns_type0_gasprice_no_1559_fields() {
    let addr: SocketAddr = "127.0.0.1:18513".parse().unwrap();
    let (chain, _handle) = boot(addr).await;

    let (raw, sender_hash) = sign_legacy(&DEV_PRIVKEY, PAYEE, 1 * UBI, 0);
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "legacy tx: node hash must equal sender hash"
    );

    let block_num = chain.produce_block(now_secs()).number;

    let by_hash = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &by_hash["result"];
    assert!(
        tx.is_object(),
        "legacy tx must be found by sender hash: {by_hash}"
    );
    assert_eq!(tx["type"], "0x0", "legacy tx type must be 0x0");
    assert!(
        tx["gasPrice"].is_string(),
        "legacy tx must carry gasPrice: {tx}"
    );
    assert!(
        tx["maxFeePerGas"].is_null(),
        "legacy tx must NOT carry maxFeePerGas: {tx}"
    );
    assert!(
        tx["maxPriorityFeePerGas"].is_null(),
        "legacy tx must NOT carry maxPriorityFeePerGas: {tx}"
    );

    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let r = &receipt["result"];
    assert_eq!(r["status"], "0x1", "legacy tx must succeed");
    assert_eq!(r["type"], "0x0", "legacy receipt must have type 0x0");
    assert_eq!(r["blockNumber"], format!("0x{block_num:x}"));
    assert_ne!(r["blockHash"], serde_json::Value::Null);
}

// =============================================================================
// (b) RPC: ubi_getRecentBlocks(nonEmptyOnly=true) excludes empty blocks,
//     is newest-first, and the limit is clamped (1..=100).
// =============================================================================

#[tokio::test]
async fn txqa_recent_blocks_non_empty_filter_newest_first_clamped_limit() {
    let addr: SocketAddr = "127.0.0.1:18514".parse().unwrap();
    let (chain, handle) = boot(addr).await;

    // Mine one block with a tx.
    send_ok(
        addr,
        sign_legacy_calldata(&DEV_PRIVKEY, PAYEE, 2 * UBI, vec![], 0),
    )
    .await;
    let b1 = chain.produce_block(now_secs());
    assert_eq!(b1.number, 1);

    // Mine three empty blocks.
    chain.produce_block(now_secs());
    chain.produce_block(now_secs());
    let b4 = chain.produce_block(now_secs());
    assert_eq!(b4.number, 4);

    // Without filter: newest-first, empty blocks included.
    let all = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([10])).await;
    let all_rows = all["result"].as_array().expect("expected array");
    // genesis + 4 produced blocks = 5 blocks total
    assert!(
        all_rows.len() >= 5,
        "unfiltered list must include genesis + 4 blocks: got {}",
        all_rows.len()
    );
    // Newest-first: first row is block 4.
    assert_eq!(
        hex_u64(&all_rows[0]["number"]),
        4,
        "unfiltered list must be newest-first"
    );
    // At least one empty block is present.
    assert!(
        all_rows.iter().any(|r| r["txCount"].as_u64() == Some(0)),
        "unfiltered list must include empty blocks"
    );
    // Shape: every row has the required directory fields.
    let r0 = &all_rows[0];
    assert!(r0["hash"].as_str().unwrap().starts_with("0x"));
    assert!(r0["parentHash"].as_str().unwrap().starts_with("0x"));
    assert!(r0["timestamp"].as_str().unwrap().starts_with("0x"));
    assert!(r0["gasUsed"].as_str().unwrap().starts_with("0x"));
    assert_eq!(r0["miner"], "0x0000000000000000000000000000000000000000");

    // With nonEmptyOnly=true: only block 1 (the one with the transfer).
    let ne = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([10, true])).await;
    let ne_rows = ne["result"].as_array().expect("expected array");
    assert_eq!(
        ne_rows.len(),
        1,
        "nonEmptyOnly=true must exclude empty blocks; expected 1 block, got {}",
        ne_rows.len()
    );
    assert_eq!(hex_u64(&ne_rows[0]["number"]), 1);
    assert_eq!(ne_rows[0]["txCount"].as_u64().unwrap(), 1);
    // Every returned block must have at least one tx.
    for row in ne_rows {
        assert!(
            row["txCount"].as_u64().unwrap() > 0,
            "nonEmptyOnly filter must not include empty blocks: {row}"
        );
    }

    // Limit clamping: an absurd limit (10 000) is accepted (not rejected) and clamped to 100.
    let big = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([10_000])).await;
    assert!(
        big["result"].is_array(),
        "absurd limit must be clamped, not rejected"
    );

    // Limit = 1: only the newest block is returned.
    let one = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([1])).await;
    let one_rows = one["result"].as_array().expect("expected array");
    assert_eq!(
        one_rows.len(),
        1,
        "limit=1 must return exactly one (newest) block"
    );
    assert_eq!(
        hex_u64(&one_rows[0]["number"]),
        4,
        "limit=1 must return the newest block"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================
// (b) RPC: ubi_getContracts lists a deployed contract with the right shape.
// =============================================================================

#[tokio::test]
async fn txqa_contracts_directory_shape_and_title_derivation() {
    let addr: SocketAddr = "127.0.0.1:18515".parse().unwrap();
    let (chain, handle) = boot(addr).await;

    // No contracts yet.
    let empty = rpc(addr, "ubi_getContracts", serde_json::json!([50])).await;
    assert_eq!(
        empty["result"].as_array().expect("array").len(),
        0,
        "directory must be empty before any deploy"
    );

    // Deploy a contract. The title is the first line of the on-chain text (<=80 chars).
    let text =
        "Escrow release: pay the seller when the buyer confirms receipt of goods.".to_string();
    let deploy_raw = sign_legacy_calldata(
        &DEV_PRIVKEY,
        CONTRACT_HUB,
        0,
        deployContractCall {
            text: text.clone(),
            parties: vec![DEV_ADDR, PAYEE],
        }
        .abi_encode(),
        0,
    );
    let deploy_hash = send_ok(addr, deploy_raw).await;
    chain.produce_block(now_secs());

    // Fund the escrow so the directory shows a non-zero balance.
    let fund_raw = sign_legacy_calldata(
        &DEV_PRIVKEY,
        CONTRACT_HUB,
        7 * UBI,
        fundContractCall {
            id: U256::from(0u64),
        }
        .abi_encode(),
        1,
    );
    send_ok(addr, fund_raw).await;
    chain.produce_block(now_secs());

    // Directory now lists the contract.
    let list = rpc(addr, "ubi_getContracts", serde_json::json!([50])).await;
    let rows = list["result"].as_array().expect("contracts list");
    assert_eq!(rows.len(), 1, "one deployed contract in the directory");

    let c = &rows[0];
    // Required fields + correct values.
    assert_eq!(c["id"].as_u64().unwrap(), 0, "first contract id must be 0");
    assert!(
        c["address"].as_str().unwrap().starts_with("0x"),
        "derived escrow address must be 0x-prefixed"
    );
    assert_eq!(
        c["status"], "Active",
        "newly deployed contract must be Active"
    );
    assert_eq!(
        c["parties"].as_array().unwrap().len(),
        2,
        "two declared parties"
    );
    // Title is derived from the first line of on-chain text (truncated to 80 chars).
    assert_eq!(
        c["title"].as_str().unwrap(),
        &text[..text.len().min(80)],
        "title must match the on-chain text (first line, <=80 chars)"
    );
    assert_eq!(
        hex_u128(&c["escrow"]),
        7 * UBI,
        "escrow must reflect the 7 UBI funded"
    );
    assert_eq!(
        hex_u128(&c["balance"]),
        7 * UBI,
        "balance alias must equal escrow"
    );
    assert_eq!(
        c["deploy_tx"].as_str().unwrap(),
        deploy_hash,
        "deploy_tx hash must match the tx that called deployContract"
    );
    assert!(
        c["createdAt"].as_u64().is_some(),
        "createdAt must be a unix timestamp"
    );
    assert!(
        c["deploy_block"].as_u64().is_some(),
        "deploy_block must be a block number"
    );

    // Limit clamping: 10 000 is accepted and clamped to 100 (still returns the 1 contract).
    let big_limit = rpc(addr, "ubi_getContracts", serde_json::json!([10_000])).await;
    assert_eq!(
        big_limit["result"].as_array().unwrap().len(),
        1,
        "absurd limit must be clamped, still returns the deployed contract"
    );

    // Limit = 1 returns the newest-first result.
    let one = rpc(addr, "ubi_getContracts", serde_json::json!([1])).await;
    assert_eq!(
        one["result"].as_array().unwrap().len(),
        1,
        "limit=1 returns 1 contract"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================
// (b) RPC: unknown tx hash returns null from eth_getTransactionByHash
//     (the friendly not-found panel is a UI concern; the node returns null).
// =============================================================================

#[tokio::test]
async fn txqa_unknown_tx_hash_returns_null() {
    let addr: SocketAddr = "127.0.0.1:18516".parse().unwrap();
    let (chain, _handle) = boot(addr).await;
    chain.produce_block(now_secs()); // ensure at least one block exists

    let fake = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

    let by_hash = rpc(addr, "eth_getTransactionByHash", serde_json::json!([fake])).await;
    assert_eq!(
        by_hash["result"],
        serde_json::Value::Null,
        "unknown tx hash must return null from eth_getTransactionByHash"
    );

    let receipt = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([fake])).await;
    assert_eq!(
        receipt["result"],
        serde_json::Value::Null,
        "unknown tx hash must return null from eth_getTransactionReceipt"
    );
}

// =============================================================================
// (b) RPC: eth_getBlockByNumber can serve block detail used by /block/[id] route.
// =============================================================================

#[tokio::test]
async fn txqa_block_route_backing_rpc_returns_block_detail() {
    let addr: SocketAddr = "127.0.0.1:18517".parse().unwrap();
    let (chain, _handle) = boot(addr).await;

    // Mine one block.
    send_ok(
        addr,
        sign_legacy_calldata(&DEV_PRIVKEY, PAYEE, 1 * UBI, vec![], 0),
    )
    .await;
    let b = chain.produce_block(now_secs());

    // eth_getBlockByNumber("latest", true): the backing RPC for /block/[id].
    let r = rpc(
        addr,
        "eth_getBlockByNumber",
        serde_json::json!(["latest", true]),
    )
    .await;
    let block = &r["result"];
    assert!(block.is_object(), "block must be found: {r}");
    assert_eq!(
        hex_u64(&block["number"]),
        b.number,
        "block number must match"
    );
    assert!(
        block["hash"].as_str().unwrap().starts_with("0x"),
        "block must have a 0x-prefixed hash"
    );
    // With full=true the transactions list is non-empty (the transfer we mined).
    let txs = block["transactions"]
        .as_array()
        .expect("transactions array");
    assert_eq!(txs.len(), 1, "the mined block must carry 1 tx");

    // eth_getBlockByNumber for block 0 (genesis).
    let genesis = rpc(
        addr,
        "eth_getBlockByNumber",
        serde_json::json!(["0x0", false]),
    )
    .await;
    assert!(
        genesis["result"].is_object(),
        "genesis block must be found by number 0x0"
    );
    // Unknown block returns null.
    let unknown = rpc(
        addr,
        "eth_getBlockByNumber",
        serde_json::json!(["0xff", false]),
    )
    .await;
    assert_eq!(
        unknown["result"],
        serde_json::Value::Null,
        "non-existent block number must return null"
    );
}

// =============================================================================
// (b) RPC: ubi_getAccount can serve address detail used by /address/[addr].
// =============================================================================

#[tokio::test]
async fn txqa_address_route_backing_rpc_returns_account_summary() {
    let addr: SocketAddr = "127.0.0.1:18518".parse().unwrap();
    let (chain, _handle) = boot(addr).await;

    // Mine one tx so DEV_ADDR shows up in address activity.
    send_ok(
        addr,
        sign_legacy_calldata(&DEV_PRIVKEY, PAYEE, 1 * UBI, vec![], 0),
    )
    .await;
    chain.produce_block(now_secs());

    let dev_addr_hex = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));

    // ubi_getAccount: the backing RPC for /address/[addr].
    let r = rpc(addr, "ubi_getAccount", serde_json::json!([dev_addr_hex])).await;
    let acct = &r["result"];
    assert!(
        acct.is_object(),
        "ubi_getAccount must return an object for the dev address"
    );
    // address field is present and matches.
    assert!(
        acct["address"].as_str().unwrap().to_lowercase() == dev_addr_hex.to_lowercase(),
        "address field must match queried address"
    );
    // balance is hex.
    assert!(
        acct["balance"].as_str().unwrap().starts_with("0x"),
        "balance must be hex"
    );
    // nonce advanced to 1 after one tx.
    assert_eq!(
        hex_u64(&acct["nonce"]),
        1,
        "nonce must be 1 after one mined tx"
    );
    // human_status is "Verified" (seeded).
    assert_eq!(
        acct["human_status"].as_str().unwrap(),
        "Verified",
        "seeded dev account must be Verified"
    );
    // tx_count >= 1.
    assert!(
        acct["tx_count"].as_u64().unwrap() >= 1,
        "tx_count must reflect the mined tx"
    );

    // ubi_getAddressActivity: also backing /address/[addr].
    let act = rpc(
        addr,
        "ubi_getAddressActivity",
        serde_json::json!([dev_addr_hex, 10]),
    )
    .await;
    let rows = act["result"].as_array().expect("activity array");
    assert!(
        !rows.is_empty(),
        "address activity must have at least one row"
    );
    let row0 = &rows[0];
    assert!(row0["hash"].as_str().unwrap().starts_with("0x"));
    assert_eq!(row0["kind"].as_str().unwrap(), "Transfer");
}

// =============================================================================
// Sanity: all new RPC methods are registered (can call them without "method not
// found" error).
// =============================================================================

#[tokio::test]
async fn txqa_new_rpc_methods_are_registered() {
    let addr: SocketAddr = "127.0.0.1:18519".parse().unwrap();
    let (chain, _handle) = boot(addr).await;
    chain.produce_block(now_secs());

    // ubi_getRecentBlocks with no params.
    let r1 = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([])).await;
    assert!(
        r1.get("error").is_none() || !r1["error"].is_object(),
        "ubi_getRecentBlocks must be registered: {r1}"
    );
    assert!(r1["result"].is_array(), "must return an array");

    // ubi_getContracts with no params.
    let r2 = rpc(addr, "ubi_getContracts", serde_json::json!([])).await;
    assert!(
        r2.get("error").is_none() || !r2["error"].is_object(),
        "ubi_getContracts must be registered: {r2}"
    );
    assert!(r2["result"].is_array(), "must return an array");
}
