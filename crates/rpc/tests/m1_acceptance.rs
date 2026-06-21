//! M1 acceptance integration test (board task M1-T7, owned by qa-engineer).
//!
//! Boots the real [`ubi2_rpc::serve`] HTTP+WS JSON-RPC server in-process on a NON-DEFAULT port
//! (`127.0.0.1:18545`, to avoid colliding with other gates' devnet on `:8545`) and drives it like a
//! standard EVM client (the same request/response a viem/ethers/MetaMask client would issue). It maps
//! the M1 spec's acceptance criteria (`docs/specs/01-evm-rpc-and-wallet.md`) to executable checks:
//!
//!   * **Criterion 1** — `connects_and_reads_chain_state`: `eth_chainId`, `eth_blockNumber` (climbing),
//!     `eth_getBalance` (streaming up), `eth_getTransactionCount`.
//!   * **Criterion 3** — `signed_transfer_settles_and_moves_balance`: a real EIP-155-signed legacy tx
//!     submitted via `eth_sendRawTransaction` settles emission, moves value, bumps the nonce, and is
//!     conserved (no UBI lost/double-counted) across settlement.
//!   * **Criterion 4** — `explorer_renders_block_and_transaction`: the mined tx is queryable through the
//!     explorer-facing methods (`eth_getBlockByNumber` full-tx, `eth_getTransactionByHash`,
//!     `eth_getTransactionReceipt`).
//!
//! Criterion 5 (reproducibility, I2) is covered by the runtime unit/property tests in
//! `crates/runtime/src/lib.rs`; criterion 2 (MetaMask) is the same RPC contract criterion 1 exercises,
//! plus a manual MetaMask check documented in `docs/reports/qa-m1.md`.
//!
//! Transactions are signed with the well-known, PUBLIC devnet key (Hardhat/Anvil account #0) — the
//! same key the node seeds as the pre-verified dev account. It is published in every Ethereum dev
//! toolkit and holds no real value.

use std::net::SocketAddr;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, U256};
use k256::ecdsa::SigningKey;

use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, EMISSION_PERIOD_SECS, UBI};

/// Well-known PUBLIC devnet key (Hardhat/Anvil account #0). NOT A SECRET — published everywhere.
///   private key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
///   address    : 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
const DEV_PRIVKEY: [u8; 32] =
    hex_literal_32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// const-fn hex decode of a 32-byte literal (so the privkey is a compile-time constant).
const fn hex_literal_32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2]);
        let lo = hex_nibble(bytes[i * 2 + 1]);
        out[i] = (hi << 4) | lo;
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

/// Sign an EIP-155 legacy value transfer with the devnet key and return the 2718-encoded raw bytes
/// (exactly what a wallet hands to `eth_sendRawTransaction`).
fn sign_transfer(to: AlloyAddr, value: u128, nonce: u64, chain_id: u64) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 21_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        input: Default::default(),
    };
    let signing_key = SigningKey::from_slice(&DEV_PRIVKEY).expect("valid devnet key");

    // EIP-155 signature hash, then a recoverable secp256k1 signature over it.
    let sighash = tx.signature_hash();
    let (sig, recid) = signing_key
        .sign_prehash_recoverable(sighash.as_slice())
        .expect("sign prehash");
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let alloy_sig =
        PrimitiveSignature::from_scalars_and_parity(r.into(), s.into(), recid.is_y_odd());

    let signed = tx.into_signed(alloy_sig);
    let envelope: TxEnvelope = signed.into();
    let mut raw = Vec::new();
    envelope.encode_2718(&mut raw);
    raw
}

/// Async JSON-RPC-over-HTTP/1.1 client (no reqwest dependency): POST one request, parse the body.
/// This drives the raw wire path a real EVM client uses, so the test exercises HTTP framing, not just
/// the in-process module. Reads headers, then exactly `Content-Length` body bytes (robust against the
/// server holding the keep-alive connection open).
async fn rpc(addr: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as AsyncTcpStream;

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

    let fut = async {
        let mut stream = AsyncTcpStream::connect(addr).await.expect("connect to rpc");
        stream
            .write_all(req.as_bytes())
            .await
            .expect("write request");
        stream.flush().await.expect("flush");

        // Read until we have full headers (terminated by CRLFCRLF).
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
                if k.trim().eq_ignore_ascii_case("content-length") {
                    v.trim().parse().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);

        // Read the remaining body bytes up to content_len.
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

    serde_json::from_str(&resp)
        .unwrap_or_else(|e| panic!("bad json from {method}: {e}\n---\n{resp}"))
}

/// Find the first index of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Decode a `0x`-prefixed hex quantity into u128.
fn hex_u128(v: &serde_json::Value) -> u128 {
    let s = v.as_str().expect("hex string result");
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("valid hex quantity")
}

/// Boot a Chain seeded with the pre-verified dev account (verified at genesis), serve it on `addr`,
/// and return the running chain (the caller keeps it + the handle alive). `genesis_time` is set well
/// in the past so a balance is already streaming when the test reads it.
async fn boot(addr: SocketAddr, genesis_time: u64) -> (Chain, jsonrpsee::server::ServerHandle) {
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis_time);
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 0,
        nonce: 0,
    });
    let handle = serve(addr, chain.clone()).await.expect("serve");
    // Give jsonrpsee a moment to bind the listener before the raw TCP client connects.
    tokio::time::sleep(Duration::from_millis(150)).await;
    (chain, handle)
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

// =============================================================================================
// Criterion 1 — a standard EVM client connects and reads correct chain state.
// =============================================================================================
#[tokio::test]
async fn connects_and_reads_chain_state() {
    let addr: SocketAddr = "127.0.0.1:18545".parse().unwrap();
    // Genesis 2 hours in the past ⇒ dev account already streamed ~2 UBI.
    let genesis = now_secs() - 2 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    // --- eth_chainId ---
    let chain_id = rpc(addr, "eth_chainId", serde_json::json!([])).await;
    assert_eq!(
        chain_id["result"], "0x5542",
        "chainId must be 0x5542 (21826)"
    );

    // --- net_version (decimal) ---
    let net = rpc(addr, "net_version", serde_json::json!([])).await;
    assert_eq!(
        net["result"], "21826",
        "net_version must be decimal chain id"
    );

    // --- eth_blockNumber climbs as blocks are produced ---
    let b0 = hex_u128(&rpc(addr, "eth_blockNumber", serde_json::json!([])).await["result"]);
    chain.produce_block(now_secs());
    chain.produce_block(now_secs());
    let b1 = hex_u128(&rpc(addr, "eth_blockNumber", serde_json::json!([])).await["result"]);
    assert_eq!(
        b1,
        b0 + 2,
        "blockNumber must climb with produced blocks (got {b0} -> {b1})"
    );

    // --- eth_getBalance is streaming and ~2 UBI for the dev account ---
    let dev = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
    let bal_a =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([dev, "latest"])).await["result"]);
    // ~2 UBI accrued (allow a few seconds of jitter around the 2h mark).
    let two_ubi = 2 * UBI;
    let tolerance = UBI / 360; // 10 seconds' worth of emission
    assert!(
        bal_a >= two_ubi - tolerance && bal_a <= two_ubi + tolerance,
        "dev balance should be ~2 UBI, got {bal_a} (expected ~{two_ubi})"
    );

    // Reading again a moment later must show a strictly larger balance (the stream ticks up).
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let bal_b =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([dev, "latest"])).await["result"]);
    assert!(
        bal_b > bal_a,
        "balance must stream upward: {bal_a} -> {bal_b}"
    );

    // --- eth_getTransactionCount (nonce) is 0 for the fresh dev account ---
    let nonce = hex_u128(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([dev, "latest"]),
        )
        .await["result"],
    );
    assert_eq!(nonce, 0, "fresh dev account nonce must be 0");

    // A never-seen address reads as zero balance / zero nonce (no panic).
    let stranger = "0x00000000000000000000000000000000000000ff";
    let s_bal = hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([stranger, "latest"]),
        )
        .await["result"],
    );
    let s_nonce = hex_u128(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([stranger, "latest"]),
        )
        .await["result"],
    );
    assert_eq!(s_bal, 0);
    assert_eq!(s_nonce, 0);

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// Criterion 3 — a signed transfer moves balance correctly with emission settled at transfer time.
// =============================================================================================
#[tokio::test]
async fn signed_transfer_settles_and_moves_balance() {
    let addr: SocketAddr = "127.0.0.1:18546".parse().unwrap();
    let genesis = now_secs() - 3 * EMISSION_PERIOD_SECS; // ~3 UBI accrued
    let (chain, handle) = boot(addr, genesis).await;

    let recipient = address!("00000000000000000000000000000000000000aa");
    let dev = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
    let rcpt = format!("0x{}", hex::encode(recipient.as_slice()));

    // Conservation baseline: total system value visible *before* the transfer.
    let pre_dev =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([dev, "latest"])).await["result"]);
    let pre_rcpt =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([rcpt, "latest"])).await["result"]);
    assert_eq!(pre_rcpt, 0, "recipient starts empty");
    assert!(
        pre_dev >= 3 * UBI - UBI / 360,
        "dev should hold ~3 UBI, got {pre_dev}"
    );

    // Sign + submit a 1 UBI transfer (nonce 0) exactly as a wallet would.
    let raw = sign_transfer(recipient, UBI, 0, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let send = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    let tx_hash = send["result"]
        .as_str()
        .unwrap_or_else(|| panic!("sendRawTransaction failed: {send}"));
    assert!(
        tx_hash.starts_with("0x") && tx_hash.len() == 66,
        "tx hash shape: {tx_hash}"
    );

    // Mine the queued tx (the node's tick task does this; here we drive it explicitly).
    let mine_ts = now_secs();
    let block = chain.produce_block(mine_ts);
    assert_eq!(
        block.txs.len(),
        1,
        "the signed transfer must be mined into the next block"
    );

    // --- Recipient now holds exactly 1 UBI; it is unverified, so it does NOT stream. ---
    let post_rcpt =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([rcpt, "latest"])).await["result"]);
    assert_eq!(
        post_rcpt, UBI,
        "recipient must hold exactly 1 UBI after the transfer"
    );

    // --- Sender nonce advanced to 1 ---
    let post_nonce = hex_u128(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([dev, "latest"]),
        )
        .await["result"],
    );
    assert_eq!(post_nonce, 1, "sender nonce must advance to 1");

    // --- Conservation (no UBI lost or double-counted across settlement) ---
    // At the mine timestamp, the dev's settled balance = (emission up to mine_ts) - 1 UBI sent.
    // Reconstruct expected dev settled value deterministically and compare to a balance read taken
    // *at* the same instant via the runtime (so the streaming component doesn't race the assertion).
    let dev_at_mine = chain.balance(&DEV_ADDR.into_array(), mine_ts);
    let rcpt_at_mine = chain.balance(&recipient.into_array(), mine_ts);
    // Total value at mine time must equal what the dev alone would have held had it not transferred:
    // dev_emission(mine_ts) (recipient is unverified ⇒ contributes no new stream).
    let expected_total = {
        // Emission for a verified account from genesis to mine_ts.
        let elapsed = (mine_ts - genesis) as u128;
        UBI.saturating_mul(elapsed) / EMISSION_PERIOD_SECS as u128
    };
    assert_eq!(
        dev_at_mine + rcpt_at_mine,
        expected_total,
        "value must be conserved exactly across the transfer+settlement"
    );
    assert_eq!(
        rcpt_at_mine, UBI,
        "recipient share is exactly the 1 UBI sent"
    );

    // --- Replay / bad-nonce protection: re-submitting the same raw tx (nonce 0) is rejected. ---
    let replay = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        replay.get("error").is_some(),
        "replaying a spent nonce must be rejected, got {replay}"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// Criterion 4 — the explorer can render a block and a transaction.
// =============================================================================================
#[tokio::test]
async fn explorer_renders_block_and_transaction() {
    let addr: SocketAddr = "127.0.0.1:18547".parse().unwrap();
    let genesis = now_secs() - 5 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    let recipient = address!("00000000000000000000000000000000000000bb");
    let raw = sign_transfer(recipient, UBI / 2, 0, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let tx_hash = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await["result"]
        .as_str()
        .expect("tx accepted")
        .to_string();

    let block = chain.produce_block(now_secs());
    let block_num_hex = format!("0x{:x}", block.number);

    // --- eth_getBlockByNumber (full tx objects) renders the block + its transaction ---
    let blk = rpc(
        addr,
        "eth_getBlockByNumber",
        serde_json::json!([block_num_hex, true]),
    )
    .await;
    let blk = &blk["result"];
    assert_eq!(blk["number"], block_num_hex, "block number echoes back");
    assert!(
        blk["hash"].as_str().unwrap().starts_with("0x"),
        "block has a hash"
    );
    assert!(
        blk["parentHash"].as_str().unwrap().starts_with("0x"),
        "block has a parentHash"
    );
    let txs = blk["transactions"].as_array().expect("transactions array");
    assert_eq!(txs.len(), 1, "the block renders its single transaction");
    assert_eq!(txs[0]["hash"], tx_hash, "embedded tx hash matches");
    assert_eq!(
        txs[0]["from"].as_str().unwrap().to_lowercase(),
        format!("0x{}", hex::encode(DEV_ADDR.as_slice())),
        "tx from is the dev account"
    );

    // --- eth_getBlockByNumber("latest", false) returns hash-only tx list (explorer list view) ---
    let latest = rpc(
        addr,
        "eth_getBlockByNumber",
        serde_json::json!(["latest", false]),
    )
    .await;
    let latest_txs = latest["result"]["transactions"].as_array().unwrap();
    assert_eq!(latest_txs[0], tx_hash, "hash-only tx listing");

    // --- eth_getTransactionByHash renders the transaction ---
    let tx = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([tx_hash]),
    )
    .await;
    let tx = &tx["result"];
    assert_eq!(tx["hash"], tx_hash);
    assert_eq!(hex_u128(&tx["value"]), UBI / 2, "tx value matches");
    assert_eq!(tx["blockNumber"], block_num_hex);

    // --- eth_getTransactionReceipt renders a successful receipt ---
    let rcpt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await;
    let rcpt = &rcpt["result"];
    assert_eq!(
        rcpt["status"], "0x1",
        "receipt status must be success (0x1)"
    );
    assert_eq!(rcpt["transactionHash"], tx_hash);
    assert_eq!(rcpt["blockNumber"], block_num_hex);

    // --- Unknown hash returns null (not an error) ---
    let unknown = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!(["0x0000000000000000000000000000000000000000000000000000000000000000"]),
    )
    .await;
    assert!(unknown["result"].is_null(), "unknown tx hash returns null");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// Local hex encoder (keeps the test self-contained, mirrors the crate's internal helper).
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
