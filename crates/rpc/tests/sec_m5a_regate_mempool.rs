//! SECURITY RE-GATE (M5 Stage A) — SEC-M5A-3 LIVE mempool-cap PoC against a spawned `ubi2-node`.
//!
//! This is a LIVE end-to-end PoC (NOT a unit test): it spawns a real `ubi2-node` process on a
//! **non-default RPC port** and floods it over JSON-RPC `eth_sendRawTransaction`. The node is started as
//! a NETWORKED FOLLOWER (P2P on a non-default loopback port, NO proposer key) so it accepts txs into the
//! mempool but never mines a block to drain it — the mempool grows under the flood until the per-sender
//! cap (`MEMPOOL_MAX_PER_SENDER`) rejects further txs from that sender. The rejection arrives as a clean
//! JSON-RPC error ("per-sender cap"), proving the unbounded-mempool DoS (SEC-M5A-3) is CLOSED at ingest.
//!
//! NON-DEFAULT ports (never the 8545 single-node devnet, never the m5_stage_a 1856x/1956x range):
//!   RPC:  127.0.0.1:18601
//!   P2P:  /ip4/127.0.0.1/tcp/19601
//!
//! Gated `#[ignore]`: the qa/security harness runs it with `--ignored` (it spawns a process + warms up).
//! Run: `cargo test -p ubi2-rpc --test sec_m5a_regate_mempool -- --ignored --nocapture`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, PrimitiveSignature, TxKind, U256};
use k256::ecdsa::SigningKey;
use ubi2_network::consts::MEMPOOL_MAX_PER_SENDER;

const RPC_PORT: u16 = 18601;
const P2P_PORT: u16 = 19601;
const CHAIN_ID: u64 = 21826; // 0x5542 (DEVNET_CHAIN_ID)

/// Anvil account #0 (PUBLIC dev key — NOT a secret); the seeded, verified genesis dev account.
const SENDER_KEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const SENDER_ADDR: &str = "f39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const PAYEE_ADDR: &str = "70997970C51812dc3A010C7d01b50e0d17dc79C8";

/// Genesis far enough in the past that the dev account has accrued plenty of UBI to fund the flood (the
/// account streams 1 UBI/hour from genesis; ~1000 hours ⇒ ~1000 UBI, far above the flood's fee+value).
const GENESIS_OFFSET_SECS: u64 = 1_000 * 3_600;

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

fn node_bin() -> PathBuf {
    let mut p = std::env::current_exe()
        .expect("current_exe")
        .parent()
        .expect("parent")
        .to_path_buf();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("ubi2-node")
}

struct NodeProc {
    child: Child,
    _data_dir: PathBuf,
}
impl Drop for NodeProc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_follower() -> NodeProc {
    let tmp = std::env::temp_dir().join(format!("ubi2-secm5a-mempool-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("tmp dir");
    let genesis_time = now_secs().saturating_sub(GENESIS_OFFSET_SECS);

    let mut cmd = Command::new(node_bin());
    cmd.env("UBI2_RPC_ADDR", format!("127.0.0.1:{RPC_PORT}"))
        // Networked FOLLOWER: P2P enabled (non-default port) but NO proposer key ⇒ never mines, so the
        // mempool is not drained by block production and the flood actually piles up against the cap.
        .env("UBI2_P2P_ADDR", format!("/ip4/127.0.0.1/tcp/{P2P_PORT}"))
        .env("UBI2_BOOTSTRAP", "") // no peers — isolated; nothing gossips our flood away
        .env("UBI2_GENESIS_TIME", genesis_time.to_string())
        .env("UBI2_BLOCK_MS", "60000") // long tick; even the follower never mines, but keep it large
        .env("UBI2_DATA_DIR", tmp.to_str().unwrap())
        .env("UBI2_MDNS", "0")
        .env("RUST_LOG", "warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .stdin(Stdio::null());
    let child = cmd.spawn().expect("spawn ubi2-node follower");
    NodeProc {
        child,
        _data_dir: tmp,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn wait_ready(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(300),
        )
        .is_ok()
        {
            std::thread::sleep(Duration::from_millis(150));
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// One JSON-RPC call; returns the parsed top-level response object (with `result` / `error`).
fn rpc(port: u16, method: &str, params: &str) -> Option<serde_json::Value> {
    let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{params}}}"#);
    let stream = std::net::TcpStream::connect_timeout(
        &format!("127.0.0.1:{port}").parse().unwrap(),
        Duration::from_millis(500),
    )
    .ok()?;
    stream
        .set_read_timeout(Some(Duration::from_millis(3000)))
        .ok()?;
    stream
        .set_write_timeout(Some(Duration::from_millis(3000)))
        .ok()?;
    let mut w = stream.try_clone().ok()?;
    let req = format!(
        "POST / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    w.write_all(req.as_bytes()).ok()?;
    drop(w);
    let mut resp = String::new();
    let mut r = stream;
    r.read_to_string(&mut resp).ok()?;
    let json = resp.find("\r\n\r\n").map(|p| resp[p + 4..].to_string())?;
    serde_json::from_str(&json).ok()
}

fn sign_transfer(value: u128, nonce: u64) -> Vec<u8> {
    let to = Address::from_slice(&hex::decode(PAYEE_ADDR));
    let tx = TxLegacy {
        chain_id: Some(CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 300_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        input: Vec::new().into(),
    };
    let sk = SigningKey::from_slice(&SENDER_KEY).unwrap();
    let sighash = tx.signature_hash();
    let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let alloy_sig =
        PrimitiveSignature::from_scalars_and_parity(r.into(), s.into(), recid.is_y_odd());
    let env: TxEnvelope = tx.into_signed(alloy_sig).into();
    let mut raw = Vec::new();
    env.encode_2718(&mut raw);
    raw
}

mod hex {
    pub fn decode(s: &str) -> Vec<u8> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }
    pub fn encode(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}

fn send_raw(port: u16, raw: &[u8]) -> Option<serde_json::Value> {
    let hexed = format!("0x{}", hex::encode(raw));
    rpc(port, "eth_sendRawTransaction", &format!(r#"["{hexed}"]"#))
}

/// SEC-M5A-3 (LIVE): flood a real node past `MEMPOOL_MAX_PER_SENDER`. The first cap txs from the dev
/// sender admit (return a tx hash); the (cap+1)-th is REJECTED with a JSON-RPC error naming the
/// per-sender cap — the mempool is bounded at ingest, not grown without limit.
#[test]
#[ignore = "spawns a ubi2-node process; run with -- --ignored"]
fn live_mempool_rejects_over_per_sender_cap() {
    let bin = node_bin();
    assert!(
        bin.exists(),
        "ubi2-node binary not found at {} — run `cargo build --workspace` first",
        bin.display()
    );

    let node = spawn_follower();
    assert!(
        wait_ready(RPC_PORT, Duration::from_secs(20)),
        "SEC-M5A-3: follower RPC port {RPC_PORT} not ready within 20s"
    );

    // Confirm the sender has accrued balance to fund the flood (sanity; emission from a back-dated genesis).
    let bal = rpc(
        RPC_PORT,
        "eth_getBalance",
        &format!(r#"["0x{SENDER_ADDR}", "latest"]"#),
    )
    .and_then(|v| v["result"].as_str().map(|s| s.to_string()))
    .unwrap_or_default();
    eprintln!("[sec-m5a-3] sender balance = {bal}");

    // Starting committed nonce (should be 0 on a fresh follower that never mines).
    let start_nonce = rpc(
        RPC_PORT,
        "eth_getTransactionCount",
        &format!(r#"["0x{SENDER_ADDR}", "latest"]"#),
    )
    .and_then(|v| v["result"].as_str().map(|s| s.to_string()))
    .map(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0))
    .unwrap_or(0);
    eprintln!("[sec-m5a-3] start committed nonce = {start_nonce}");

    // Admit exactly MEMPOOL_MAX_PER_SENDER txs at successive nonces (value 1 wei each; cheap but real).
    let mut admitted = 0usize;
    for i in 0..MEMPOOL_MAX_PER_SENDER as u64 {
        let raw = sign_transfer(1, start_nonce + i);
        let resp = send_raw(RPC_PORT, &raw).expect("rpc reachable");
        if resp.get("result").and_then(|r| r.as_str()).is_some() {
            admitted += 1;
        } else {
            panic!(
                "SEC-M5A-3: tx {i} within the per-sender cap should admit but got: {}",
                resp
            );
        }
    }
    assert_eq!(
        admitted, MEMPOOL_MAX_PER_SENDER,
        "all {MEMPOOL_MAX_PER_SENDER} txs within the per-sender cap admitted"
    );
    eprintln!("[sec-m5a-3] admitted {admitted} txs up to the per-sender cap");

    // The (cap+1)-th tx from the SAME sender must be REJECTED at the per-sender cap (JSON-RPC error).
    let over_raw = sign_transfer(1, start_nonce + MEMPOOL_MAX_PER_SENDER as u64);
    let over = send_raw(RPC_PORT, &over_raw).expect("rpc reachable for over-cap tx");
    eprintln!("[sec-m5a-3] over-cap response = {over}");
    assert!(
        over.get("result").is_none() || over["result"].is_null(),
        "SEC-M5A-3: an over-cap tx must NOT be admitted (no tx hash result); got {over}"
    );
    let err_msg = over
        .get("error")
        .and_then(|e| e["message"].as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        err_msg.contains("per-sender cap"),
        "SEC-M5A-3: the over-cap rejection must name the per-sender cap; got error: {err_msg:?}"
    );
    eprintln!("[sec-m5a-3] PASS: over-cap tx rejected with: {err_msg}");

    drop(node);
}
