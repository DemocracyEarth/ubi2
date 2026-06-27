//! UI explorer directory reads integration test (board task: minimal read-only RPCs the UI batch needs).
//!
//! Boots the real [`ubi2_rpc::serve`] HTTP JSON-RPC server in-process (NON-DEFAULT port) and drives it
//! like a standard EVM client — the same wire path the explorer uses. Covers the two new directory reads:
//!
//! * `ubi_getRecentBlocks(limit, nonEmptyOnly?)` → compact block summaries (newest-first). Acceptance:
//!   with `nonEmptyOnly=true` the result excludes the empty 2s-tick blocks and lists only blocks that
//!   actually contain txs (most devnet blocks are empty).
//! * `ubi_getContracts(limit)` → the global deployed-contracts directory. Acceptance: after a deploy
//!   the list returns the deployed contract (id/address/parties/status/title/escrow), newest-first.
//!
//! Every assertion is on a deterministic shape (hex quantities, 0x addresses/hashes) the node computes
//! purely from stored blocks/state — no model calls (the deterministic Mock impls run at block time).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::contracts::{deployContractCall, fundContractCall, CONTRACT_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, MockInterpreter, UBI};

/// Well-known PUBLIC devnet keys (Hardhat/Anvil accounts). NOT SECRETS.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
/// A payee account (Anvil acct #5) — receives a plain transfer + is a contract party.
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

/// Sign an EIP-155 legacy tx to `to` with `value` + `calldata` under `key`, returning 2718 raw bytes.
fn sign_tx(key: &[u8; 32], to: AlloyAddr, value: u128, input: Vec<u8>, nonce: u64) -> Vec<u8> {
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
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    raw
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
fn hex_u128(v: &serde_json::Value) -> u128 {
    let s = v.as_str().expect("hex string");
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex quantity")
}
fn hex_u64(v: &serde_json::Value) -> u64 {
    let s = v.as_str().expect("hex string");
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex quantity")
}

/// Send a signed raw tx; assert it was accepted (returns a tx-hash string).
async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send failed: {resp}"))
        .to_string()
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Boot a Chain with the dev account (a funded Verified human) running the deterministic
/// MockInterpreter, served over HTTP.
async fn boot(addr: SocketAddr, genesis: u64) -> (Chain, jsonrpsee::server::ServerHandle) {
    let chain =
        Chain::new(DEVNET_CHAIN_ID, genesis).with_interpreter(Arc::new(MockInterpreter::default()));
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

/// `ubi_getRecentBlocks` with `nonEmptyOnly=true` excludes empty tick blocks and lists only blocks
/// that contain transactions; without the filter the empty blocks are present.
#[tokio::test]
async fn recent_blocks_non_empty_filter_excludes_empty_blocks() {
    let addr: SocketAddr = "127.0.0.1:18591".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // Block 1: a plain transfer (NON-EMPTY).
    let tx_hash = send_ok(addr, sign_tx(&DEV_PRIVKEY, PAYEE, 3 * UBI, Vec::new(), 0)).await;
    let b1 = chain.produce_block(now_secs());
    assert_eq!(b1.number, 1);

    // Blocks 2,3,4: empty ticks (no mempool).
    chain.produce_block(now_secs());
    chain.produce_block(now_secs());
    let b4 = chain.produce_block(now_secs());
    assert_eq!(b4.number, 4);

    // Without the filter: the most-recent blocks include the empty ticks (newest-first).
    let all = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([10])).await;
    let all_rows = all["result"].as_array().expect("blocks list");
    assert!(all_rows.len() >= 5, "genesis + 4 blocks present");
    // Newest-first: first row is block 4.
    assert_eq!(hex_u64(&all_rows[0]["number"]), 4, "newest-first ordering");
    // Some empty blocks are present in the unfiltered list.
    assert!(
        all_rows.iter().any(|r| r["txCount"].as_u64() == Some(0)),
        "unfiltered list contains empty blocks"
    );
    // Shape: a recent-block row carries the directory fields.
    let r0 = &all_rows[0];
    assert!(r0["hash"].as_str().unwrap().starts_with("0x"));
    assert!(r0["parentHash"].as_str().unwrap().starts_with("0x"));
    assert!(r0["timestamp"].as_str().unwrap().starts_with("0x"));
    assert!(r0["gasUsed"].as_str().unwrap().starts_with("0x"));
    assert_eq!(r0["miner"], "0x0000000000000000000000000000000000000000");

    // With nonEmptyOnly=true: ONLY blocks that contain txs — the empty ticks are excluded.
    let ne = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([10, true])).await;
    let ne_rows = ne["result"].as_array().expect("non-empty blocks list");
    assert!(
        !ne_rows.is_empty(),
        "the transfer block survives the filter"
    );
    for row in ne_rows {
        assert!(
            row["txCount"].as_u64().unwrap() > 0,
            "nonEmptyOnly excludes empty blocks, got {row}"
        );
    }
    // The only non-empty block is block 1 (the transfer).
    assert_eq!(ne_rows.len(), 1, "exactly one non-empty block");
    assert_eq!(hex_u64(&ne_rows[0]["number"]), 1, "the transfer block");
    assert_eq!(ne_rows[0]["txCount"].as_u64().unwrap(), 1);
    // The tx we sent is the one in that block.
    let _ = tx_hash;

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// `ubi_getContracts` returns a deployed contract in the global directory (newest-first), with its
/// id/address/parties/status/title and the funded escrow balance.
#[tokio::test]
async fn contracts_directory_lists_deployed_contract() {
    let addr: SocketAddr = "127.0.0.1:18592".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // No contracts yet → empty directory.
    let empty = rpc(addr, "ubi_getContracts", serde_json::json!([50])).await;
    assert_eq!(
        empty["result"].as_array().expect("array").len(),
        0,
        "no contracts deployed yet"
    );

    // Deploy a contract.
    let deploy_hash = send_ok(
        addr,
        sign_tx(
            &DEV_PRIVKEY,
            CONTRACT_HUB,
            0,
            deployContractCall {
                text: "Escrow agreement: pay the payee on delivery".to_string(),
                parties: vec![DEV_ADDR, PAYEE],
            }
            .abi_encode(),
            0,
        ),
    )
    .await;
    chain.produce_block(now_secs());

    // Fund the escrow so the directory shows a non-zero balance.
    send_ok(
        addr,
        sign_tx(
            &DEV_PRIVKEY,
            CONTRACT_HUB,
            10 * UBI,
            fundContractCall {
                id: U256::from(0u64),
            }
            .abi_encode(),
            1,
        ),
    )
    .await;
    chain.produce_block(now_secs());

    // The global directory now lists the deployed contract.
    let list = rpc(addr, "ubi_getContracts", serde_json::json!([50])).await;
    let rows = list["result"].as_array().expect("contracts list");
    assert_eq!(rows.len(), 1, "one deployed contract in the directory");
    let c = &rows[0];
    assert_eq!(c["id"].as_u64().unwrap(), 0, "first contract id");
    assert!(
        c["address"].as_str().unwrap().starts_with("0x"),
        "derived escrow address"
    );
    assert_eq!(c["status"], "Active");
    assert_eq!(
        c["parties"].as_array().unwrap().len(),
        2,
        "two declared parties"
    );
    assert_eq!(
        c["title"], "Escrow agreement: pay the payee on delivery",
        "title derived from the on-chain text"
    );
    assert_eq!(
        hex_u128(&c["escrow"]),
        10 * UBI,
        "escrow reflects the funded amount"
    );
    assert_eq!(
        hex_u128(&c["balance"]),
        10 * UBI,
        "balance alias equals escrow"
    );
    assert!(
        c["deploy_tx"].as_str().unwrap().starts_with("0x"),
        "deploy tx hash present"
    );
    // The createdAt resolves the deploy block's timestamp (>= genesis).
    assert!(
        c["createdAt"].as_u64().unwrap() >= genesis,
        "createdAt is the deploy block timestamp"
    );
    let _ = deploy_hash;

    // Limit is bounded: an absurd limit is clamped, not rejected.
    let bounded = rpc(addr, "ubi_getContracts", serde_json::json!([10_000])).await;
    assert_eq!(
        bounded["result"].as_array().unwrap().len(),
        1,
        "limit clamped, still returns the one contract"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
