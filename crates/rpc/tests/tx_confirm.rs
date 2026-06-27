//! tx_confirm — MetaMask "Dropped" regression suite (cycle-7).
//!
//! Root cause this guards against: MetaMask signs a TYPE-2 (EIP-1559) transaction on this chain — the
//! node advertises `baseFeePerGas` on blocks and `eth_feeHistory`, so MetaMask picks the 1559 fee
//! market. After sending, MetaMask polls `eth_getTransactionByHash`/`Receipt` by the hash it computed
//! and reconciles the returned object against the one it signed. The tx HASH is the canonical EIP-2718
//! hash and is type-independent, so it matched — but `tx_to_json`/`receipt_to_json` hardcoded
//! `"type": "0x0"` and omitted `maxFeePerGas`/`maxPriorityFeePerGas`. MetaMask saw a type-mismatched
//! object, concluded a *different* tx took the nonce, and showed the (correctly mined, state-changing)
//! tx as "Dropped".
//!
//! These tests sign EXACTLY as MetaMask does (an EIP-1559 type-2 tx, chainId 0x5542) and assert the
//! node (a) accepts it, (b) returns the SAME hash the sender computed, and (c) `getTransactionByHash`
//! /`getTransactionReceipt` find it under that hash with the right `blockNumber`, `status: 0x1`, and
//! `type: 0x2` plus the 1559 fee fields. Covered: a type-2 value transfer, a type-2 ContractHub
//! deploy, and a type-0 legacy transfer (must still work).

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

use ubi2_rpc::contracts::{deployContractCall, CONTRACT_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, MockInterpreter};

/// Well-known PUBLIC devnet key (Hardhat/Anvil account #0). NOT A SECRET — published everywhere.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
/// Anvil account #1 — a transfer recipient.
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

/// Sign a type-2 (EIP-1559) tx EXACTLY as MetaMask does on this chain (1559 fee market, chainId
/// 0x5542): `maxFeePerGas`/`maxPriorityFeePerGas` + an empty access list. Returns BOTH the 2718 raw
/// bytes the wallet hands to `eth_sendRawTransaction` AND the tx hash the SENDER computed — so the
/// test can assert the node returns the same hash and finds the tx under it.
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
        // MetaMask sets these from `eth_feeHistory` + `eth_maxPriorityFeePerGas`. The priority tip is 0
        // on this chain; the max fee just needs to cover the flat base fee.
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

/// Sign a legacy (type-0) EIP-155 transfer — the pre-1559 path, which must still work.
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

/// Async JSON-RPC-over-HTTP/1.1 client (no reqwest): POST one request, parse the body.
async fn rpc(addr: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as AsyncTcpStream;

    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
        .to_string();
    let req = format!(
        "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let fut = async {
        let mut stream = AsyncTcpStream::connect(addr).await.expect("connect");
        stream.write_all(req.as_bytes()).await.expect("write");
        stream.flush().await.expect("flush");
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let header_end = loop {
            if let Some(pos) = find_subsequence(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.expect("read headers");
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let header_str = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let content_len: usize = header_str
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (k.trim().eq_ignore_ascii_case("content-length"))
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

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Send a signed raw tx; assert it was accepted and return the node's reported hash string.
async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send failed: {resp}"))
        .to_string()
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Boot a chain with the dev account as a funded Verified human (accrued UBI to spend / fund escrows).
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

// =============================================================================================
// A type-2 (EIP-1559) value transfer is accepted, mined, and found by the SENDER's hash with the
// right blockNumber, status 0x1, and type 0x2 + 1559 fee fields. This is the exact MetaMask flow.
// =============================================================================================
#[tokio::test]
async fn type2_transfer_confirms_with_type_and_1559_fields() {
    let addr: SocketAddr = "127.0.0.1:18601".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600; // dev account has streamed ~100 UBI
    let (chain, _handle) = boot(addr, genesis).await;

    // Sign EXACTLY as MetaMask: a type-2 tx. Capture the hash the SENDER computed.
    let (raw, sender_hash) = sign_1559(
        &DEV_PRIVKEY,
        PAYEE,
        123_000_000_000_000_000,
        vec![],
        0,
        21_000,
    );
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    // (a) the node ACCEPTS the type-2 tx and (b) returns the SAME hash the sender computed.
    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "node must return the sender's canonical 2718 hash for a type-2 tx"
    );

    let block = chain.produce_block(now_secs()).number;

    // (c) getTransactionByHash(senderHash) finds it with type 0x2 + 1559 fields + a real blockNumber.
    let by_hash = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &by_hash["result"];
    assert!(
        tx.is_object(),
        "tx must be found by the sender hash (not null): {by_hash}"
    );
    assert_eq!(tx["type"], "0x2", "tx type must echo the signed type-2");
    assert_eq!(
        tx["blockNumber"],
        format!("0x{block:x}"),
        "tx must report the block it was mined in (non-null)"
    );
    assert_ne!(
        tx["blockHash"],
        serde_json::Value::Null,
        "blockHash must be set"
    );
    assert!(
        tx["maxFeePerGas"].is_string(),
        "type-2 tx must carry maxFeePerGas: {tx}"
    );
    assert!(
        tx["maxPriorityFeePerGas"].is_string(),
        "type-2 tx must carry maxPriorityFeePerGas: {tx}"
    );
    assert_eq!(
        tx["maxFeePerGas"], "0x77359400",
        "echoes the signed 2 gwei max fee"
    );
    assert_eq!(tx["maxPriorityFeePerGas"], "0x0", "echoes the signed 0 tip");
    assert!(
        tx["accessList"].is_array(),
        "type-2 tx must carry an accessList"
    );
    assert_eq!(tx["chainId"], "0x5542");

    // getTransactionReceipt(senderHash): status 0x1, type 0x2, the right block.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let r = &receipt["result"];
    assert!(
        r.is_object(),
        "receipt must be found by the sender hash: {receipt}"
    );
    assert_eq!(
        r["status"], "0x1",
        "a successful transfer must report status 0x1"
    );
    assert_eq!(r["type"], "0x2", "receipt type must echo the signed type-2");
    assert_eq!(r["blockNumber"], format!("0x{block:x}"));
    assert_ne!(r["blockHash"], serde_json::Value::Null);

    // And the state actually moved (this is what made the "Dropped" report a contradiction).
    let bal = rpc(
        addr,
        "eth_getBalance",
        serde_json::json!([format!("0x{}", hex::encode(PAYEE.as_slice())), "latest"]),
    )
    .await;
    let payee_bal =
        u128::from_str_radix(bal["result"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    assert_eq!(
        payee_bal, 123_000_000_000_000_000,
        "the transfer credited the payee"
    );
}

// =============================================================================================
// A type-2 ContractHub deploy is accepted, mined, and found by the sender's hash with type 0x2,
// status 0x1, and the ContractDeployed log — so a deploy shows Confirmed in MetaMask, not Dropped.
// =============================================================================================
#[tokio::test]
async fn type2_contract_deploy_confirms() {
    let addr: SocketAddr = "127.0.0.1:18602".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    let contract_text = "On the agreed signal, pay 5 UBI from escrow to the payee.".to_string();
    let calldata = deployContractCall {
        text: contract_text,
        parties: vec![DEV_ADDR, PAYEE],
    }
    .abi_encode();

    // Sign the deploy as MetaMask would: a type-2 tx to the ContractHub.
    let (raw, sender_hash) = sign_1559(&DEV_PRIVKEY, CONTRACT_HUB, 0, calldata, 0, 400_000);
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "deploy: node hash must match sender hash"
    );

    let block = chain.produce_block(now_secs()).number;

    let by_hash = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let tx = &by_hash["result"];
    assert!(
        tx.is_object(),
        "deploy tx must be found by sender hash: {by_hash}"
    );
    assert_eq!(tx["type"], "0x2", "deploy tx type must echo type-2");
    assert_eq!(
        tx["to"],
        format!("0x{}", hex::encode(CONTRACT_HUB.as_slice()))
    );
    assert!(tx["maxFeePerGas"].is_string(), "deploy carries 1559 fields");

    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let r = &receipt["result"];
    assert!(r.is_object(), "deploy receipt must be found: {receipt}");
    assert_eq!(
        r["status"], "0x1",
        "a valid deploy must succeed (status 0x1)"
    );
    assert_eq!(r["type"], "0x2", "deploy receipt type must echo type-2");
    assert_eq!(r["blockNumber"], format!("0x{block:x}"));
    let logs = r["logs"]
        .as_array()
        .expect("deploy emits a ContractDeployed log");
    assert_eq!(logs.len(), 1, "exactly one ContractDeployed log: {logs:?}");
}

// =============================================================================================
// A legacy (type-0) transfer still works — find-by-hash returns type 0x0, status 0x1, no 1559 fields.
// =============================================================================================
#[tokio::test]
async fn legacy_transfer_still_confirms_as_type0() {
    let addr: SocketAddr = "127.0.0.1:18603".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, _handle) = boot(addr, genesis).await;

    let (raw, sender_hash) = sign_legacy(&DEV_PRIVKEY, PAYEE, 1_000_000_000_000_000_000, 0);
    let sender_hash_hex = format!("0x{}", hex::encode(sender_hash.as_slice()));

    let node_hash = send_ok(addr, raw).await;
    assert_eq!(
        node_hash, sender_hash_hex,
        "legacy: node hash must match sender hash"
    );

    let block = chain.produce_block(now_secs()).number;

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
    assert_eq!(tx["type"], "0x0", "legacy tx must report type 0x0");
    assert!(
        tx["maxFeePerGas"].is_null(),
        "a legacy tx must NOT carry 1559 fields"
    );
    assert!(tx["gasPrice"].is_string(), "a legacy tx carries gasPrice");

    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([sender_hash_hex]),
    )
    .await;
    let r = &receipt["result"];
    assert_eq!(r["status"], "0x1");
    assert_eq!(r["type"], "0x0", "legacy receipt must report type 0x0");
    assert_eq!(r["blockNumber"], format!("0x{block:x}"));
}
