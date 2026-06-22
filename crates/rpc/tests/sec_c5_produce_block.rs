//! C5-SEC-3 regression: a LIVE (blocking-client) LLM backend driven through `produce_block` must NOT
//! panic the block-production task, and must yield a committed/aborted outcome.
//!
//! Before the fix, `produce_block` was awaited inline on the node's async block loop, and the live
//! transports use `reqwest::blocking`. Dropping a blocking client's inner runtime inside an async context
//! panics ("Cannot drop a runtime in a context where blocking is not allowed"), killing the node — and the
//! triggering op (`requestVerification`) is fee-exempt and submittable by anyone. The fix runs each block
//! tick on the blocking pool (`tokio::task::spawn_blocking`), so the blocking client is dropped on a
//! blocking-allowed thread.
//!
//! This test reproduces the exact hazard WITHOUT touching a real provider (I5): a stub `HumanityOracle`
//! whose `grade_liveness` constructs and uses a `reqwest::blocking::Client` against a refused loopback
//! port (so it returns fast with a deterministic abort, no network egress). We submit a real signed
//! `requestVerification` so `produce_block` actually invokes the oracle, then drive the tick the way
//! `main.rs` does — `spawn_blocking(move || chain.produce_block(...))` on a multi-thread runtime — and
//! assert the join succeeds (no panic) and the block was produced.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::humanity::{requestVerificationCall, HUMANITY_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{
    Account, Address, CanonicalVerdict, Confidence, GraphView, HumanityOracle, Verdict,
};

const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const VOUCHER2: AlloyAddr = address!("15d34AAf54267DB7D7c367839AAf71A00a2C6A65");
const JUROR1: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
const JUROR2: AlloyAddr = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
const JUROR3: AlloyAddr = address!("90F79bf6EB2c4f870365E785982E1f101E93b906");

const SUBJECT_KEY: [u8; 32] =
    hex32("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");

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

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

/// A stub `HumanityOracle` that uses a **blocking** reqwest client — the same hazard a live backend poses.
/// Every method makes a blocking HTTP request to a refused loopback port (a connection error returns fast,
/// no network egress) and then maps the failure to a deterministic abort verdict (`Uncertain`/`Low`),
/// exactly as the real `ClaudeOracle` does on a transport error. The point is to drop a blocking client's
/// runtime within `produce_block`: if that runs on the async runtime thread it panics; on the blocking
/// pool it does not.
struct BlockingStubOracle;

impl BlockingStubOracle {
    fn blocking_call_then_abort(&self) -> CanonicalVerdict {
        // Build + use a blocking client (this is the construct that panics on inner-runtime drop in an
        // async context). The target is a refused loopback port so it fails fast with no egress.
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(200))
            .build()
            .expect("client");
        let _ = client.post("http://127.0.0.1:1/never").body("{}").send();
        // Deterministic fail-closed abort (mirrors the real oracle's transport-error path).
        CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low)
    }
}

impl HumanityOracle for BlockingStubOracle {
    fn grade_liveness(&self, _challenge: &[u8], _response: &[u8]) -> CanonicalVerdict {
        self.blocking_call_then_abort()
    }
    fn analyze_sybil(&self, _graph: &GraphView, _subject: &Address) -> CanonicalVerdict {
        self.blocking_call_then_abort()
    }
    fn adjudicate(&self, _evidence: &[u8]) -> CanonicalVerdict {
        self.blocking_call_then_abort()
    }
}

fn sign_tx(key: &[u8; 32], to: AlloyAddr, value: u128, input: Vec<u8>, nonce: u64) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(DEVNET_CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 200_000,
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
        let mut buf = Vec::new();
        stream.read_to_end(&mut buf).await.expect("read");
        let s = String::from_utf8_lossy(&buf);
        s.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
    };
    let resp = tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .expect("rpc timed out");
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("bad json: {e}\n{resp}"))
}

/// Drive a signed `requestVerification` through `produce_block` run on the blocking pool (as `main.rs`
/// does) with a blocking-client-backed oracle. Assert: the spawn_blocking join succeeds (NO PANIC) and a
/// block was produced with the tx mined.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_blocking_backend_through_produce_block_does_not_panic() {
    let addr: SocketAddr = "127.0.0.1:18599".parse().unwrap();
    let genesis = now_secs() - 1000;

    let mut chain = Chain::new(DEVNET_CHAIN_ID, genesis);
    // Swap in the blocking-client oracle (stands in for a live backend).
    chain = chain.with_oracle(Arc::new(BlockingStubOracle));

    // Seed the founder humans + jurors so the case lifecycle has its substrate (mirrors the node genesis).
    for a in [DEV_ADDR, VOUCHER2] {
        chain.seed_account(Account {
            address: a.into_array(),
            verified: true,
            verified_at: genesis,
            last_settled_at: genesis,
            settled_balance: 0,
            nonce: 0,
        });
        chain.seed_verified_human(&a.into_array(), genesis);
    }
    for j in [JUROR1, JUROR2, JUROR3] {
        chain.seed_account(Account {
            address: j.into_array(),
            verified: true,
            verified_at: genesis,
            last_settled_at: genesis,
            settled_balance: 0,
            nonce: 0,
        });
        chain.register_juror(&j.into_array(), 0);
    }

    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(150)).await;

    // A fresh subject submits requestVerification → opens a Registration case; produce_block will invoke
    // the (blocking-client) oracle's grade_liveness on this op.
    let liveness_ref = B256::from([0x11u8; 32]);
    let raw = sign_tx(
        &SUBJECT_KEY,
        HUMANITY_HUB,
        0,
        requestVerificationCall {
            livenessRef: liveness_ref,
        }
        .abi_encode(),
        0,
    );
    let raw_hex = format!("0x{}", hex_encode(&raw));
    let sent = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        sent["result"].is_string(),
        "requestVerification accepted: {sent}"
    );

    // Drive produce_block EXACTLY as main.rs now does: on the blocking pool. The join MUST succeed
    // (no panic from dropping the blocking client's runtime), and the block must include the mined tx.
    let tick_chain = chain.clone();
    let join = tokio::task::spawn_blocking(move || tick_chain.produce_block(now_secs())).await;
    let block = join.expect("produce_block tick must NOT panic on a live blocking backend");
    assert_eq!(
        block.txs.len(),
        1,
        "the requestVerification tx was mined (committed/aborted outcome reached, not a crash)"
    );

    // The node is still alive and serving (the loop did not die).
    let head = rpc(addr, "eth_blockNumber", serde_json::json!([])).await;
    assert!(
        head["result"].is_string(),
        "node still serving after the tick: {head}"
    );

    handle.stop().expect("stop");
    let _ = handle.stopped().await;
}
