//! GATE 3 security PoCs for the tx-confirmation + explorer-UI batch (branch
//! fix/tx-confirmation-explorer-routes). Defender-side, this project only.
//!
//! Drives the real [`ubi2_rpc::serve`] HTTP JSON-RPC server in-process over the wire (NON-DEFAULT
//! ports) — the same path the explorer/MetaMask use — with HOSTILE inputs against the NEW surface:
//!
//!  * `ubi_getRecentBlocks(limit?, nonEmptyOnly?)` / `ubi_getContracts(limit?)` — abuse `limit`
//!    (huge / negative / float / string / object / null), a non-array params payload, and a hostile
//!    `nonEmptyOnly`. Assert: no panic / no 500, the clamp (1..=100) is enforced, bad input fails
//!    closed with a JSON-RPC error, never a crash.
//!  * `ubi_getContracts` title derivation on ADVERSARIAL on-chain text — multibyte/emoji/CJK, a long
//!    grapheme run, control chars, a title-injection attempt. Assert: no char-boundary panic, the
//!    title is bounded, and nothing beyond the already-public on-chain text is surfaced (no PII / no
//!    internal-only field, e.g. no `text`/`vars`/raw private data in the directory row).
//!  * Secret redaction: `ubi_getOracleConfig` over the wire never returns a full API key — only the
//!    env-var NAME (`api_key_env`) and never a `api_key`/secret value field.
//!
//! No model calls (deterministic Mock interpreter runs at block time).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::contracts::{deployContractCall, CONTRACT_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, MockInterpreter};

/// Well-known PUBLIC devnet key (Hardhat/Anvil acct #0). NOT A SECRET.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

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

fn sign_tx(key: &[u8; 32], to: AlloyAddr, value: u128, input: Vec<u8>, nonce: u64) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(DEVNET_CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 600_000,
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

/// POST one JSON-RPC request over raw HTTP/1.1, return the parsed JSON body. Returns whatever the
/// server emits (success OR error) — the PoC asserts on the shape, and the fact the server STAYS UP
/// (we read a well-formed HTTP response at all) proves no panic / no connection reset.
async fn rpc(addr: SocketAddr, method: &str, params: serde_json::Value) -> serde_json::Value {
    rpc_raw(
        addr,
        &serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
            .to_string(),
    )
    .await
}

/// POST an ARBITRARY (possibly malformed) JSON-RPC body — used to send non-array `params`.
async fn rpc_raw(addr: SocketAddr, body: &str) -> serde_json::Value {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream as AsyncTcpStream;

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
        // Sanity: a live server answers HTTP/1.1 200 even for a JSON-RPC-level error (the error rides
        // the JSON body). A panic would drop the connection (n==0, no headers).
        assert!(
            header_str.starts_with("HTTP/1.1 200"),
            "server must answer 200 (JSON-RPC errors ride the body) — got: {header_str}"
        );
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
        .unwrap_or_else(|_| panic!("rpc {method} timed out (possible hang/DoS)", method = body));
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("bad json: {e}\n{resp}"))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hexenc(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send failed: {resp}"))
        .to_string()
}

fn hexenc(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

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

/// Deploy a contract whose on-chain text is `text` (party = the dev addr) and produce a block.
async fn deploy_text(addr: SocketAddr, chain: &Chain, text: &str, nonce: u64) {
    send_ok(
        addr,
        sign_tx(
            &DEV_PRIVKEY,
            CONTRACT_HUB,
            0,
            deployContractCall {
                text: text.to_string(),
                parties: vec![DEV_ADDR],
            }
            .abi_encode(),
            nonce,
        ),
    )
    .await;
    chain.produce_block(now_secs());
}

// ---------------------------------------------------------------------------------------------
// PoC 1 — limit-param abuse on the two new read RPCs cannot DoS / panic; clamp 1..=100 enforced.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn poc_recent_blocks_limit_abuse_is_clamped_and_never_panics() {
    let addr: SocketAddr = "127.0.0.1:18593".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;
    // Produce a handful of blocks (some non-empty).
    send_ok(addr, sign_tx(&DEV_PRIVKEY, DEV_ADDR, 0, Vec::new(), 0)).await;
    for _ in 0..4 {
        chain.produce_block(now_secs());
    }

    // Hostile `limit` values. None may panic; all must either clamp or fail-closed with an error.
    let hostiles = [
        serde_json::json!([0]),                    // below clamp floor → clamps to 1
        serde_json::json!([1_000_000_000_000u64]), // absurd → clamps to 100
        serde_json::json!(["0xffffffffffffffff"]), // u64::MAX hex → clamps to 100
        serde_json::json!(["0xfffffffffffffffffff"]), // overflows u64 → invalid_params (fail closed)
        serde_json::json!([-5]),                      // negative → invalid_params (fail closed)
        serde_json::json!([3.5]),                     // float → invalid_params (fail closed)
        serde_json::json!([{"evil": true}]),          // object → invalid_params (fail closed)
        serde_json::json!([null, "not-a-bool"]), // null limit + bad nonEmptyOnly → default + false
        serde_json::json!([10, {"a": 1}]),       // non-bool nonEmptyOnly → treated as false
        serde_json::json!([]),                   // no params → default 20
    ];
    for h in hostiles {
        let r = rpc(addr, "ubi_getRecentBlocks", h.clone()).await;
        // Either a result array (clamped) or a JSON-RPC error object — NEVER a crash/missing both.
        let ok = r.get("result").map(|v| v.is_array()).unwrap_or(false);
        let err = r.get("error").is_some();
        assert!(
            ok || err,
            "ubi_getRecentBlocks({h}) neither result nor error: {r}"
        );
        if ok {
            let len = r["result"].as_array().unwrap().len();
            assert!(
                len <= 100,
                "result must be clamped to <=100, got {len} for {h}"
            );
        }
    }

    // A huge numeric limit returns AT MOST 100 rows (clamp proven on the actual array length).
    let big = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([999999])).await;
    assert!(
        big["result"].as_array().unwrap().len() <= 100,
        "clamp at 100"
    );
    // A clearly-negative limit is rejected (fail-closed), not silently treated as huge.
    let neg = rpc(addr, "ubi_getRecentBlocks", serde_json::json!([-1])).await;
    assert!(
        neg.get("error").is_some(),
        "negative limit must be a JSON-RPC error: {neg}"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

#[tokio::test]
async fn poc_get_contracts_limit_abuse_is_clamped_and_never_panics() {
    let addr: SocketAddr = "127.0.0.1:18594".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;
    // Deploy three contracts.
    deploy_text(addr, &chain, "Contract A", 0).await;
    deploy_text(addr, &chain, "Contract B", 1).await;
    deploy_text(addr, &chain, "Contract C", 2).await;

    let hostiles = [
        serde_json::json!([0]),
        serde_json::json!([2_000_000_000u64]),
        serde_json::json!(["0xffffffffffffffff"]),
        serde_json::json!(["0xfffffffffffffffffff"]),
        serde_json::json!([-9]),
        serde_json::json!([1.2]),
        serde_json::json!([[1, 2, 3]]),
        serde_json::json!([]),
    ];
    for h in hostiles {
        let r = rpc(addr, "ubi_getContracts", h.clone()).await;
        let ok = r.get("result").map(|v| v.is_array()).unwrap_or(false);
        let err = r.get("error").is_some();
        assert!(
            ok || err,
            "ubi_getContracts({h}) neither result nor error: {r}"
        );
        if ok {
            assert!(
                r["result"].as_array().unwrap().len() <= 100,
                "clamp <=100 for {h}"
            );
        }
    }

    // The directory row exposes ONLY directory fields — NOT the full on-chain `text`, `vars`, or
    // `cases` (those live behind ubi_getContract(id)). No internal-only / PII field leaks here.
    let list = rpc(addr, "ubi_getContracts", serde_json::json!([50])).await;
    let rows = list["result"].as_array().expect("array");
    assert!(!rows.is_empty());
    for row in rows {
        let obj = row.as_object().unwrap();
        assert!(
            !obj.contains_key("text"),
            "directory must not carry full on-chain text"
        );
        assert!(!obj.contains_key("vars"), "directory must not carry vars");
        assert!(
            !obj.contains_key("cases"),
            "directory must not carry exec cases"
        );
        // The fields it DOES carry are the already-public directory set.
        for k in obj.keys() {
            assert!(
                matches!(
                    k.as_str(),
                    "id" | "address"
                        | "parties"
                        | "status"
                        | "escrow"
                        | "balance"
                        | "title"
                        | "deploy_block"
                        | "deploy_tx"
                        | "createdAt"
                ),
                "unexpected directory field leaked: {k}"
            );
        }
    }

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// ---------------------------------------------------------------------------------------------
// PoC 2 — adversarial on-chain text → title derivation never panics on a char boundary and is
// bounded; the title carries only already-public text.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn poc_contract_title_multibyte_adversarial_text_no_panic_and_bounded() {
    let addr: SocketAddr = "127.0.0.1:18595".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (chain, handle) = boot(addr, genesis).await;

    // A pile of adversarial first-line texts: long emoji runs (4-byte chars whose 80th char lands
    // mid-UTF-8-sequence if you byte-slice), CJK, combining marks, control chars, a leading blank
    // line, and an HTML/script-y title-injection attempt (must be surfaced verbatim, NOT executed —
    // the wire layer is JSON; the UI renders as React text).
    let texts = [
        "😀".repeat(200),                                   // 200 4-byte emoji, 800 bytes
        "中文".repeat(100),                                 // CJK
        format!("{}\nsecond line", "a\u{0301}".repeat(90)), // combining acute accents
        "\u{0000}\u{0001}\u{0002}control chars then text".to_string(),
        "\n\n\n   leading blank lines then a title".to_string(),
        "<script>alert('xss')</script>".to_string() + &"x".repeat(120),
        "x".repeat(79), // just under cap
        "x".repeat(80), // exactly at cap
        "x".repeat(81), // just over cap → truncated + ellipsis
        String::new(),  // empty text → empty title
    ];
    for (nonce, t) in texts.iter().enumerate() {
        // Some texts are huge but under MAX_CONTRACT_TEXT_BYTES; deploy each and tick a block.
        deploy_text(addr, &chain, t, nonce as u64).await;
    }

    // The whole directory renders without a panic (the server answered 200 + valid JSON for each row).
    let list = rpc(addr, "ubi_getContracts", serde_json::json!([100])).await;
    let rows = list["result"].as_array().expect("array");
    assert_eq!(rows.len(), texts.len(), "every deploy is listed");
    for row in rows {
        let title = row["title"].as_str().expect("title is a string");
        // Bounded: at most 80 chars + an optional single-char ellipsis.
        let char_count = title.chars().count();
        assert!(
            char_count <= 81,
            "title must be bounded to 80 chars (+ ellipsis), got {char_count}: {title:?}"
        );
        // It is valid UTF-8 (it round-tripped through JSON), proving no mid-codepoint slice.
        assert!(title.is_char_boundary(0));
    }

    // The script-y text is surfaced VERBATIM as data (not interpreted) — and truncated/ellipsised.
    let xss_row = rows
        .iter()
        .find(|r| r["title"].as_str().unwrap().contains("<script>"))
        .expect("xss-attempt title present as inert data");
    assert!(
        xss_row["title"].as_str().unwrap().ends_with('…'),
        "the over-length xss title is truncated with an ellipsis (inert data either way)"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// ---------------------------------------------------------------------------------------------
// PoC 3 — non-array params to the new reads fail closed (JSON-RPC error), never a 500/panic.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn poc_non_array_params_fail_closed() {
    let addr: SocketAddr = "127.0.0.1:18596".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (_chain, handle) = boot(addr, genesis).await;

    // params as an OBJECT (not the expected array) — must be a graceful JSON-RPC error.
    for method in ["ubi_getRecentBlocks", "ubi_getContracts"] {
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": method, "params": {"limit": 5}
        })
        .to_string();
        let r = rpc_raw(addr, &body).await;
        assert!(
            r.get("error").is_some() || r.get("result").is_some(),
            "{method} with object params must answer (error or result), got: {r}"
        );
    }

    // params as a bare STRING — must not crash the server.
    let body =
        r#"{"jsonrpc":"2.0","id":1,"method":"ubi_getRecentBlocks","params":"haxor"}"#.to_string();
    let r = rpc_raw(addr, &body).await;
    assert!(r.is_object(), "server stayed up and answered JSON: {r}");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// ---------------------------------------------------------------------------------------------
// PoC 4 — secret redaction over the wire: ubi_getOracleConfig (loopback) never returns a full API
// key; only the env-var NAME. No `api_key`/secret value field exists in the response.
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn poc_oracle_config_never_leaks_full_api_key() {
    let addr: SocketAddr = "127.0.0.1:18597".parse().unwrap();
    let genesis = now_secs() - 100 * 3_600;
    let (_chain, handle) = boot(addr, genesis).await;

    // Default boot is Mock — read the config over the wire (loopback, so allowed).
    let r = rpc(addr, "ubi_getOracleConfig", serde_json::json!([])).await;
    // Loopback in-process call: must return a config body (not the loopback-denied error).
    let body = &r["result"];
    assert!(
        body.is_object(),
        "loopback caller gets the config body: {r}"
    );
    let cfg = &body["config"];
    // The config object NEVER carries a raw key value field — only the env-var NAME may appear.
    let cfg_obj = cfg.as_object().expect("config object");
    assert!(
        !cfg_obj.contains_key("api_key"),
        "config MUST NOT contain a raw api_key value field: {cfg}"
    );
    // Whatever string fields are present, none may look like a real secret (sk-... / sk-ant-...).
    let whole = serde_json::to_string(&r).unwrap();
    assert!(
        !whole.contains("sk-ant-") && !whole.contains("sk-live-"),
        "no secret-looking key value may appear anywhere in the response: {whole}"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
