//! issue #36 — `eth_getTransactionCount` must return the PENDING nonce, not the committed one.
//!
//! Root cause this guards against: the handler returned only `account.nonce` (the committed nonce as
//! of the last mined block) and ignored the mempool. But the SUBMIT gate (`ingest_raw_tx`) requires
//! `expected_nonce = acct.nonce + sender_pending`. So a wallet that sends tx A (nonce N) and then,
//! before A is mined, reads `eth_getTransactionCount` again, got N back, signed tx B with N, and the
//! node rejected B "nonce too low". Rapid successive sends broke.
//!
//! This test drives the REAL handler over HTTP (exactly as a wallet does) and asserts the count tracks
//! un-mined mempool txs: it rises as txs are admitted, is tag-sensitive (`pending`/`latest` include
//! pending; `earliest` does not), and falls back to the committed nonce once a block drains the mempool.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, hex, Address as AlloyAddr, PrimitiveSignature, TxKind, U256};
use k256::ecdsa::SigningKey;

use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, MockInterpreter};

/// Well-known PUBLIC devnet key (Hardhat/Anvil account #0). NOT A SECRET — published everywhere.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
/// Anvil account #1 — the transfer recipient.
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

/// Sign a legacy (type-0) EIP-155 transfer — a minimal, always-valid tx to occupy a mempool slot.
fn sign_legacy(key: &[u8; 32], to: AlloyAddr, value: u128, nonce: u64) -> Vec<u8> {
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

/// `eth_getTransactionCount(DEV_ADDR, tag)` → the returned count as a u64.
async fn tx_count(addr: SocketAddr, tag: &str) -> u64 {
    let dev = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
    let resp = rpc(
        addr,
        "eth_getTransactionCount",
        serde_json::json!([dev, tag]),
    )
    .await;
    let s = resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("no result: {resp}"));
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
}

/// Submit a signed raw tx; assert the node accepted it (leaves it in the mempool, un-mined).
async fn send_ok(addr: SocketAddr, raw: Vec<u8>) {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        resp["result"].as_str().is_some(),
        "send must be accepted: {resp}"
    );
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Boot a chain with the dev account as a funded Verified human (streamed UBI to spend on the txs).
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
// The pending nonce rises with un-mined mempool txs (the #36 fix), is tag-sensitive, and falls
// back to the committed nonce once a block drains the mempool.
// =============================================================================================
#[tokio::test]
async fn pending_nonce_tracks_mempool() {
    let addr: SocketAddr = "127.0.0.1:18641".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600; // dev account has streamed ~100 UBI
    let (chain, _handle) = boot(addr, genesis).await;

    // Fresh account: no mined txs, empty mempool → 0 for every tag.
    assert_eq!(tx_count(addr, "pending").await, 0, "fresh: pending == 0");
    assert_eq!(tx_count(addr, "latest").await, 0, "fresh: latest == 0");

    // Admit tx nonce 0 WITHOUT mining it. The committed nonce is still 0, but the pending nonce must
    // advance to 1 — otherwise a wallet would sign its next tx with nonce 0 again (the #36 bug).
    send_ok(
        addr,
        sign_legacy(&DEV_PRIVKEY, PAYEE, 1_000_000_000_000_000, 0),
    )
    .await;
    assert_eq!(
        tx_count(addr, "pending").await,
        1,
        "one un-mined tx ⇒ pending nonce 1"
    );
    assert_eq!(
        tx_count(addr, "latest").await,
        1,
        "MetaMask calls with `latest` and must also see the pending nonce (issue #36)"
    );
    // A historical tag has no pending txs to add ⇒ still the committed nonce (0 here).
    assert_eq!(
        tx_count(addr, "earliest").await,
        0,
        "`earliest` is the committed nonce, not the pending one"
    );

    // Admit the next tx (nonce 1, the pending nonce we just reported) — it must be ACCEPTED, proving
    // the reported nonce is the one the submit gate expects. Pending nonce then advances to 2.
    send_ok(
        addr,
        sign_legacy(&DEV_PRIVKEY, PAYEE, 1_000_000_000_000_000, 1),
    )
    .await;
    assert_eq!(
        tx_count(addr, "pending").await,
        2,
        "two un-mined txs ⇒ pending nonce 2"
    );

    // Mine a block: the mempool drains, the two txs commit, and the committed nonce catches up to 2.
    // With nothing pending, every tag now agrees on 2.
    let mined = chain.produce_block(now_secs());
    assert_eq!(mined.number, 1, "one block produced");
    assert_eq!(
        tx_count(addr, "pending").await,
        2,
        "after mining: committed nonce == 2, nothing pending"
    );
    assert_eq!(
        tx_count(addr, "latest").await,
        2,
        "after mining: latest == 2"
    );
}
