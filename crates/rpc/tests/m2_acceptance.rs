//! M2 streaming acceptance integration test (board tasks M2-T2/M2-T3).
//!
//! Boots the real [`ubi2_rpc::serve`] HTTP+WS JSON-RPC server in-process (NON-DEFAULT ports to avoid
//! colliding with the M1 gate / devnet) and drives it like a standard EVM client — the same wire path
//! a wallet uses. Maps the M2 spec's acceptance criteria (`docs/specs/02-streaming.md`) to checks:
//!
//!   * **Stream path** (criteria 1–4) — `stream_lock_accrual_solvency_stop`: sign an `openStream` tx
//!     dev→fresh recipient, assert the deposit is locked, the recipient's `eth_getBalance` climbs at
//!     `rate`, accrued caps at `deposit` past `t_end` (solvency), then `stopStream` pays accrued +
//!     refunds the remainder with totals conserved.
//!   * **NFT** (criteria 7–8) — `nft_two_tokens_owner_and_token_uri`: `ownerOf(streamId)`==recipient
//!     and `ownerOf(streamId|SENDER_FLAG)`==sender via `eth_call`; decode `tokenURI(streamId)` →
//!     base64 JSON → confirm `name`/`attributes`/`image`, and that the inline SVG decodes and carries
//!     the streamed amount + status.
//!
//! Txs are signed with the well-known PUBLIC devnet key (Hardhat/Anvil account #0) — the key the node
//! seeds as the pre-verified dev account. NOT A SECRET.

use std::net::SocketAddr;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::streams::{
    balanceOfCall, nameCall, openStreamCall, ownerOfCall, stopStreamCall, supportsInterfaceCall,
    symbolCall, tokenURICall, transferFromCall, IFACE_ERC165, IFACE_ERC721, IFACE_ERC721_METADATA,
};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{fee_for_gas, Account, EMISSION_PERIOD_SECS, GAS_STREAM, TREASURY, UBI};

/// Well-known PUBLIC devnet key (Hardhat/Anvil account #0). NOT A SECRET — published everywhere.
const DEV_PRIVKEY: [u8; 32] =
    hex_literal_32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// The StreamHub system address (`0x…5742`) stream ops + ERC-721 calls target.
const STREAM_HUB: AlloyAddr = address!("0000000000000000000000000000000000005742");

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

/// Sign an EIP-155 legacy tx to `to` with `value` + `calldata`, returning the 2718-encoded raw bytes
/// (exactly what a wallet hands to `eth_sendRawTransaction`).
fn sign_tx(to: AlloyAddr, value: u128, input: Vec<u8>, nonce: u64, chain_id: u64) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 200_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        input: input.into(),
    };
    let signing_key = SigningKey::from_slice(&DEV_PRIVKEY).expect("valid devnet key");
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

/// Async JSON-RPC-over-HTTP/1.1 client (no reqwest): POST one request, parse the body.
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
        String::from_utf8_lossy(&body_bytes).to_string()
    };

    let resp = tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("rpc {method} timed out"));
    serde_json::from_str(&resp)
        .unwrap_or_else(|e| panic!("bad json from {method}: {e}\n---\n{resp}"))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex_u128(v: &serde_json::Value) -> u128 {
    let s = v.as_str().expect("hex string result");
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("valid hex quantity")
}

/// Decode a `0x`-hex string into bytes.
fn decode_hex(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Issue an `eth_call` to StreamHub with ABI calldata, returning the raw return bytes.
async fn eth_call_hub(addr: SocketAddr, data: Vec<u8>) -> Vec<u8> {
    let data_hex = format!("0x{}", hex::encode(&data));
    let resp = rpc(
        addr,
        "eth_call",
        serde_json::json!([{ "to": format!("0x{}", hex::encode(STREAM_HUB.as_slice())), "data": data_hex }, "latest"]),
    )
    .await;
    let out = resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("eth_call error: {resp}"));
    decode_hex(out)
}

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

// =============================================================================================
// Stream path — criteria 1–4: lock → accrual → solvency cap → stop/refund conservation.
// =============================================================================================
#[tokio::test]
async fn stream_lock_accrual_solvency_stop() {
    let addr: SocketAddr = "127.0.0.1:18555".parse().unwrap();
    // Genesis far enough in the past that the dev account can fund the deposit from emission.
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS; // ~50 UBI accrued
    let (chain, handle) = boot(addr, genesis).await;

    let recipient = address!("00000000000000000000000000000000000000c1");
    let dev = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
    let rcpt = format!("0x{}", hex::encode(recipient.as_slice()));

    // 1 base unit/sec rate; 4-hours-worth deposit (clean t_end at open_at + 4h).
    let rate: u128 = 1;
    let deposit: u128 = (4 * EMISSION_PERIOD_SECS) as u128;

    // --- Criterion 1: open locks the deposit. Baseline sender spendable first. ---
    let pre_dev =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([dev, "latest"])).await["result"]);
    assert_eq!(
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([rcpt, "latest"])).await["result"]),
        0,
        "recipient starts empty"
    );

    let open_data = openStreamCall {
        to: recipient,
        ratePerSec: U256::from(rate),
        deposit: U256::from(deposit),
    }
    .abi_encode();
    let raw = sign_tx(STREAM_HUB, 0, open_data, 0, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let send = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    let tx_hash = send["result"]
        .as_str()
        .unwrap_or_else(|| panic!("openStream send failed: {send}"))
        .to_string();

    // Mine the open at a known timestamp.
    let open_at = now_secs();
    let block = chain.produce_block(open_at);
    assert_eq!(block.txs.len(), 1, "openStream mined");

    // The receipt carries the assigned stream id + the two ERC-721 mints.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await;
    let logs = receipt["result"]["logs"].as_array().expect("logs array");
    // StreamOpened + 2 Transfer mints.
    assert_eq!(
        logs.len(),
        3,
        "open emits StreamOpened + 2 Transfer mints, got {logs:?}"
    );
    let stream_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();
    println!("[stream] opened stream id = {stream_id}");

    // Deposit locked: sender spendable dropped by ~deposit (within a few seconds' emission jitter).
    let post_dev =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([dev, "latest"])).await["result"]);
    let drop = pre_dev.saturating_sub(post_dev);
    let jitter = 10 * UBI / EMISSION_PERIOD_SECS as u128 * 3; // a few seconds of emission
    assert!(
        drop >= deposit.saturating_sub(jitter),
        "sender spendable must drop by ~deposit: dropped {drop}, deposit {deposit}"
    );
    println!("[stream] deposit locked: sender spendable {pre_dev} -> {post_dev} (Δ {drop})");

    // --- Criterion 2: recipient balance climbs at `rate` (1 base unit/sec). ---
    let r1 = chain.balance(&recipient.into_array(), open_at + 1_000);
    let r2 = chain.balance(&recipient.into_array(), open_at + 2_500);
    assert_eq!(r1, rate * 1_000, "recipient accrued rate*1000 at +1000s");
    assert_eq!(r2, rate * 2_500, "recipient accrued rate*2500 at +2500s");
    println!("[stream] accrual: +1000s = {r1}, +2500s = {r2} base units (rate={rate}/s)");

    // --- Criterion 3: solvency — accrued caps at deposit far past t_end. ---
    let t_end = open_at + 4 * EMISSION_PERIOD_SECS;
    let far = open_at + 365 * 24 * EMISSION_PERIOD_SECS; // a year out
    let capped = chain.balance(&recipient.into_array(), far);
    assert_eq!(
        capped, deposit,
        "accrued must cap at deposit past t_end (solvency)"
    );
    println!("[stream] solvency: recipient balance a year past open = {capped} == deposit {deposit} (t_end={t_end})");

    // --- Criterion 4: stop pays accrued + refunds remainder; totals conserved. ---
    // Stop 1 hour in: recipient should hold 3600 base units, refund = deposit - 3600.
    let stop_at = open_at + EMISSION_PERIOD_SECS;
    // Conservation baseline at stop_at: sender + recipient + still-locked escrow.
    let pre_sender = chain.balance(&DEV_ADDR.into_array(), stop_at);
    let pre_rcpt = chain.balance(&recipient.into_array(), stop_at);
    let pre_locked = {
        let s = chain.get_stream(stream_id).unwrap();
        s.deposit - s.accrued(stop_at)
    };
    // The treasury already holds the openStream tx's UBI gas fee; the stopStream tx adds another.
    // Including it on both sides keeps conservation exact: the stop neither creates nor destroys value,
    // it just moves accrued→recipient, refund→sender, and the stop fee→treasury.
    let pre_treasury = chain.balance(&TREASURY, stop_at);
    let pre_total = pre_sender + pre_rcpt + pre_locked + pre_treasury;

    let stop_data = stopStreamCall {
        id: U256::from(stream_id),
    }
    .abi_encode();
    let raw = sign_tx(STREAM_HUB, 0, stop_data, 1, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let send = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(send["result"].is_string(), "stopStream send failed: {send}");
    chain.produce_block(stop_at);

    let post_sender = chain.balance(&DEV_ADDR.into_array(), stop_at);
    let post_rcpt = chain.balance(&recipient.into_array(), stop_at);
    let accrued_to_stop = rate * EMISSION_PERIOD_SECS as u128; // 3600 base units
    assert_eq!(
        post_rcpt, accrued_to_stop,
        "recipient paid exactly accrued-to-stop"
    );
    // Frozen: no more accrual after stop.
    assert_eq!(
        chain.balance(
            &recipient.into_array(),
            stop_at + 100 * EMISSION_PERIOD_SECS
        ),
        accrued_to_stop,
        "accrual frozen after stop"
    );

    // Conservation: post total (escrow now fully released) == pre total. The treasury grew by exactly
    // the stopStream UBI gas fee, so including it on both sides keeps the equality exact.
    let post_treasury = chain.balance(&TREASURY, stop_at);
    assert_eq!(
        post_treasury - pre_treasury,
        fee_for_gas(GAS_STREAM),
        "the stopStream UBI gas fee accrued to the treasury"
    );
    let post_total = post_sender + post_rcpt + post_treasury;
    assert_eq!(
        post_total, pre_total,
        "stop must conserve totals: pre {pre_total} != post {post_total}"
    );
    let refund = deposit - accrued_to_stop;
    println!(
        "[stream] stop@+1h: recipient paid {accrued_to_stop}, sender refunded {refund}; \
         conservation pre={pre_total} post={post_total} OK"
    );

    // ubi_getStream reflects the stopped status + the stored fields. `accrued_now` is evaluated at
    // the server's wall clock (here ~open_at, before the future stop instant), so it reads as the
    // accrued-so-far at *now* and is bounded by the accrued-to-stop cap — we assert the invariant
    // (status frozen, fields echoed, accrued ≤ cap) rather than a time-racing exact value.
    let view = rpc(addr, "ubi_getStream", serde_json::json!([stream_id])).await;
    let v = &view["result"];
    assert_eq!(v["status"]["type"], "Stopped", "view shows Stopped");
    assert_eq!(v["id"].as_u64().unwrap(), stream_id, "view id matches");
    assert_eq!(hex_u128(&v["rate"]), rate, "view rate matches");
    assert_eq!(hex_u128(&v["deposit"]), deposit, "view deposit matches");
    assert!(
        hex_u128(&v["accrued_now"]) <= accrued_to_stop,
        "view accrued_now bounded by the accrued-to-stop cap"
    );
    println!("[stream] ubi_getStream: {v}");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// NFT — criteria 7–8: two tokens (owner per side), supportsInterface, tokenURI → JSON → SVG.
// =============================================================================================
#[tokio::test]
async fn nft_two_tokens_owner_and_token_uri() {
    let addr: SocketAddr = "127.0.0.1:18556".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    let recipient = address!("00000000000000000000000000000000000000d2");
    // Realistic UBI-scale values so the card renders meaningful amounts: ~1 UBI/hr over a 24 UBI
    // deposit (drains in ~24h). The dev account holds ~50 UBI of emission, so the deposit is funded.
    let rate: u128 = UBI / EMISSION_PERIOD_SECS as u128; // ~1 UBI/hr
    let deposit: u128 = 24 * UBI;

    // Open a stream dev → recipient, mined 6 hours in the PAST so that at the wall-clock read time the
    // recipient has accrued ~6 UBI of the 24 UBI deposit (~25%) — a meaningful, eyeball-able card.
    let open_data = openStreamCall {
        to: recipient,
        ratePerSec: U256::from(rate),
        deposit: U256::from(deposit),
    }
    .abi_encode();
    let raw = sign_tx(STREAM_HUB, 0, open_data, 0, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    let open_at = now_secs() - 6 * EMISSION_PERIOD_SECS;
    chain.produce_block(open_at);
    let stream_id = chain.streams_of(&DEV_ADDR.into_array()).0[0];

    let sender_flag = U256::from(1u8) << 255;
    let recipient_token = U256::from(stream_id);
    let sender_token = U256::from(stream_id) | sender_flag;

    // --- supportsInterface(0x80ac58cd) == true (ERC-721). ---
    let si = supportsInterfaceCall {
        interfaceId: IFACE_ERC721.into(),
    }
    .abi_encode();
    let out = eth_call_hub(addr, si).await;
    let yes = supportsInterfaceCall::abi_decode_returns(&out, true)
        .unwrap()
        ._0;
    assert!(yes, "supportsInterface(0x80ac58cd) must be true");
    println!("[nft] supportsInterface(0x80ac58cd) = {yes}");

    // --- ownerOf(streamId) == recipient; ownerOf(streamId|SENDER_FLAG) == sender. ---
    let out = eth_call_hub(
        addr,
        ownerOfCall {
            tokenId: recipient_token,
        }
        .abi_encode(),
    )
    .await;
    let owner_r = ownerOfCall::abi_decode_returns(&out, true).unwrap()._0;
    assert_eq!(owner_r, recipient, "ownerOf(streamId) == recipient");

    let out = eth_call_hub(
        addr,
        ownerOfCall {
            tokenId: sender_token,
        }
        .abi_encode(),
    )
    .await;
    let owner_s = ownerOfCall::abi_decode_returns(&out, true).unwrap()._0;
    assert_eq!(owner_s, DEV_ADDR, "ownerOf(streamId|SENDER_FLAG) == sender");
    println!("[nft] ownerOf(recipient_token)={owner_r}, ownerOf(sender_token)={owner_s}");

    // --- balanceOf: recipient owns 1, sender owns 1. ---
    let out = eth_call_hub(addr, balanceOfCall { owner: recipient }.abi_encode()).await;
    let bal_r = balanceOfCall::abi_decode_returns(&out, true).unwrap()._0;
    let out = eth_call_hub(addr, balanceOfCall { owner: DEV_ADDR }.abi_encode()).await;
    let bal_s = balanceOfCall::abi_decode_returns(&out, true).unwrap()._0;
    assert_eq!(
        bal_r,
        U256::from(1u8),
        "recipient owns its 1 incoming token"
    );
    assert_eq!(bal_s, U256::from(1u8), "sender owns its 1 receipt token");
    println!("[nft] balanceOf(recipient)={bal_r}, balanceOf(sender)={bal_s}");

    // --- tokenURI(streamId) → data:application/json;base64 → JSON with name/attributes/image. ---
    let out = eth_call_hub(
        addr,
        tokenURICall {
            tokenId: recipient_token,
        }
        .abi_encode(),
    )
    .await;
    let uri = tokenURICall::abi_decode_returns(&out, true).unwrap()._0;
    assert!(
        uri.starts_with("data:application/json;base64,"),
        "tokenURI must be a base64 JSON data-URI"
    );
    let json_b64 = uri.strip_prefix("data:application/json;base64,").unwrap();
    let json_bytes = b64_decode(json_b64);
    let json = String::from_utf8(json_bytes).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&json).expect("tokenURI JSON parses");
    assert!(
        meta["name"].as_str().unwrap().contains("UBI Stream"),
        "has name"
    );
    assert!(meta["attributes"].is_array(), "has attributes array");
    let image = meta["image"].as_str().expect("has image");
    assert!(
        image.starts_with("data:image/svg+xml;base64,"),
        "image is an inline SVG data-URI"
    );
    println!("[nft] tokenURI name = {}", meta["name"]);
    println!("[nft] tokenURI attributes = {}", meta["attributes"]);

    // --- The image base64 decodes to a valid <svg…>…</svg> carrying the streamed amount + status. ---
    let svg_b64 = image.strip_prefix("data:image/svg+xml;base64,").unwrap();
    let svg = String::from_utf8(b64_decode(svg_b64)).unwrap();
    assert!(svg.starts_with("<svg"), "SVG starts with <svg");
    assert!(svg.contains("</svg>"), "SVG well-closed");
    assert!(svg.contains("Active"), "card shows Active status");
    assert!(
        svg.contains("UBI"),
        "card shows the UBI unit / streamed amount"
    );
    assert!(
        svg.contains("Incoming"),
        "recipient token card shows the Incoming badge"
    );
    // Eyeball snippet: print the head + the headline/progress region.
    println!(
        "[nft] decoded SVG (first 600 chars):\n{}",
        &svg[..svg.len().min(600)]
    );
    if let Some(pos) = svg.find("streamed") {
        let start = pos.saturating_sub(120);
        println!(
            "[nft] SVG streamed region:\n{}",
            &svg[start..(pos + 60).min(svg.len())]
        );
    }

    // --- Soulbound: transferFrom on StreamHub reverts. ---
    let transfer = transferFromCall {
        from: DEV_ADDR,
        to: recipient,
        tokenId: sender_token,
    }
    .abi_encode();
    let raw = sign_tx(STREAM_HUB, 0, transfer, 1, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        resp.get("error").is_some(),
        "transfer must revert (soulbound), got {resp}"
    );
    let msg = resp["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("soulbound"),
        "revert reason mentions soulbound: {msg}"
    );
    println!("[nft] soulbound: transferFrom rejected with '{msg}'");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// Stream reads — criterion 6: `ubi_getStreams(address)` returns the correct in/out split with live
// `accrued_now` for BOTH parties, over the real RPC wire (the surface the SDK/wallet reads).
// =============================================================================================
#[tokio::test]
async fn ubi_get_streams_in_out_split_and_live_accrual() {
    let addr: SocketAddr = "127.0.0.1:18557".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS; // ~50 UBI of dev emission to fund deposits
    let (chain, handle) = boot(addr, genesis).await;

    let recipient = address!("00000000000000000000000000000000000000e3");
    let dev = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
    let rcpt = format!("0x{}", hex::encode(recipient.as_slice()));

    // 1 base unit/sec; deposit drains in 4h (clean t_end). Open ~2h in the PAST so a live read shows a
    // meaningful, non-zero accrued (≈ 2h * 1/s = 7200 base units), still well under the deposit cap.
    let rate: u128 = 1;
    let deposit: u128 = (4 * EMISSION_PERIOD_SECS) as u128;
    let open_data = openStreamCall {
        to: recipient,
        ratePerSec: U256::from(rate),
        deposit: U256::from(deposit),
    }
    .abi_encode();
    let raw = sign_tx(STREAM_HUB, 0, open_data, 0, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    let open_at = now_secs() - 2 * EMISSION_PERIOD_SECS;
    chain.produce_block(open_at);
    let stream_id = chain.streams_of(&DEV_ADDR.into_array()).0[0];

    // --- Sender side: exactly one OUTGOING stream, no incoming. ---
    let sender_view = rpc(addr, "ubi_getStreams", serde_json::json!([dev])).await;
    let s = &sender_view["result"];
    let out = s["outgoing"].as_array().expect("outgoing array");
    assert_eq!(out.len(), 1, "sender has exactly one outgoing stream");
    assert!(
        s["incoming"].as_array().expect("incoming array").is_empty(),
        "sender has no incoming streams"
    );
    let osv = &out[0];
    assert_eq!(
        osv["id"].as_u64().unwrap(),
        stream_id,
        "outgoing id matches"
    );
    assert_eq!(
        osv["from"].as_str().unwrap().to_lowercase(),
        dev.to_lowercase(),
        "outgoing `from` is the sender"
    );
    assert_eq!(
        osv["to"].as_str().unwrap().to_lowercase(),
        rcpt.to_lowercase(),
        "outgoing `to` is the recipient"
    );
    assert_eq!(osv["status"]["type"], "Active", "stream is Active");
    assert_eq!(hex_u128(&osv["rate"]), rate, "view rate matches");
    assert_eq!(hex_u128(&osv["deposit"]), deposit, "view deposit matches");

    // --- Recipient side: the SAME stream appears as INCOMING, no outgoing. ---
    let rcpt_view = rpc(addr, "ubi_getStreams", serde_json::json!([rcpt])).await;
    let r = &rcpt_view["result"];
    let inc = r["incoming"].as_array().expect("incoming array");
    assert_eq!(inc.len(), 1, "recipient has exactly one incoming stream");
    assert!(
        r["outgoing"].as_array().expect("outgoing array").is_empty(),
        "recipient has no outgoing streams"
    );
    assert_eq!(
        inc[0]["id"].as_u64().unwrap(),
        stream_id,
        "incoming id matches the same stream"
    );

    // --- Live accrual: `accrued_now` is non-zero (≈2h of flow), still ≤ the deposit cap. The server
    // evaluates it at its own wall clock, so we assert the live-drip invariant rather than a racing
    // exact value: 0 < accrued_now ≤ deposit, and it cross-checks the runtime's own `accrued`. ---
    let accrued_now = hex_u128(&inc[0]["accrued_now"]);
    assert!(
        accrued_now > 0,
        "incoming stream is dripping (accrued_now > 0), got {accrued_now}"
    );
    assert!(
        accrued_now <= deposit,
        "accrued_now never exceeds the deposit cap (solvency), got {accrued_now}"
    );
    // Cross-check: matches the runtime's own accrued at a fixed near-now instant (monotone bound).
    let runtime_accrued = chain.get_stream(stream_id).unwrap().accrued(now_secs());
    assert!(
        accrued_now <= runtime_accrued,
        "view accrued_now ({accrued_now}) ≤ runtime accrued ({runtime_accrued})"
    );
    println!(
        "[reads] ubi_getStreams: sender out=1/in=0, recipient in=1/out=0; \
         live accrued_now={accrued_now} (≤ deposit {deposit}); id={stream_id}"
    );

    // --- `ubi_getStream(unknown)` returns null (no panic on a non-existent id). ---
    let missing = rpc(addr, "ubi_getStream", serde_json::json!([999_999])).await;
    assert!(missing["result"].is_null(), "unknown stream id reads null");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// ERC-721 collection metadata + the eth_call soulbound path — rounds out criterion 7 over the wire:
// supportsInterface for all three declared ids, name()/symbol() == the collection identity, and a
// soulbound mutator simulated through `eth_call` reverts (not just the write tx path).
// =============================================================================================
#[tokio::test]
async fn erc721_collection_metadata_and_eth_call_soulbound() {
    let addr: SocketAddr = "127.0.0.1:18558".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    let recipient = address!("00000000000000000000000000000000000000f4");
    let rate: u128 = UBI / EMISSION_PERIOD_SECS as u128;
    let deposit: u128 = 24 * UBI;
    let open_data = openStreamCall {
        to: recipient,
        ratePerSec: U256::from(rate),
        deposit: U256::from(deposit),
    }
    .abi_encode();
    let raw = sign_tx(STREAM_HUB, 0, open_data, 0, DEVNET_CHAIN_ID);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    chain.produce_block(now_secs() - EMISSION_PERIOD_SECS);
    let stream_id = chain.streams_of(&DEV_ADDR.into_array()).0[0];

    // supportsInterface: ERC-165, ERC-721, and ERC-721 Metadata all answer true; a bogus id is false.
    for (iface, label) in [
        (IFACE_ERC165, "ERC165"),
        (IFACE_ERC721, "ERC721"),
        (IFACE_ERC721_METADATA, "ERC721Metadata"),
    ] {
        let out = eth_call_hub(
            addr,
            supportsInterfaceCall {
                interfaceId: iface.into(),
            }
            .abi_encode(),
        )
        .await;
        let yes = supportsInterfaceCall::abi_decode_returns(&out, true)
            .unwrap()
            ._0;
        assert!(yes, "supportsInterface({label}) must be true");
    }
    let out = eth_call_hub(
        addr,
        supportsInterfaceCall {
            interfaceId: [0xde, 0xad, 0xbe, 0xef].into(),
        }
        .abi_encode(),
    )
    .await;
    let bogus = supportsInterfaceCall::abi_decode_returns(&out, true)
        .unwrap()
        ._0;
    assert!(!bogus, "supportsInterface(0xdeadbeef) must be false");
    println!("[nft] supportsInterface: ERC165/ERC721/ERC721Metadata = true, bogus = false");

    // name()/symbol() == the collection identity ("UBI Streams" / "USTREAM").
    let out = eth_call_hub(addr, nameCall {}.abi_encode()).await;
    let name = nameCall::abi_decode_returns(&out, true).unwrap()._0;
    let out = eth_call_hub(addr, symbolCall {}.abi_encode()).await;
    let symbol = symbolCall::abi_decode_returns(&out, true).unwrap()._0;
    assert_eq!(name, "UBI Streams", "collection name");
    assert_eq!(symbol, "USTREAM", "collection symbol");
    println!("[nft] name()='{name}', symbol()='{symbol}'");

    // Soulbound through `eth_call` (a wallet *simulating* a transfer before sending): must revert.
    let sim = transferFromCall {
        from: DEV_ADDR,
        to: recipient,
        tokenId: U256::from(stream_id),
    }
    .abi_encode();
    let data_hex = format!("0x{}", hex::encode(&sim));
    let resp = rpc(
        addr,
        "eth_call",
        serde_json::json!([
            { "to": format!("0x{}", hex::encode(STREAM_HUB.as_slice())), "data": data_hex },
            "latest"
        ]),
    )
    .await;
    assert!(
        resp.get("error").is_some(),
        "eth_call transferFrom must revert (soulbound), got {resp}"
    );
    let msg = resp["error"]["message"].as_str().unwrap_or("");
    assert!(
        msg.contains("soulbound"),
        "eth_call revert reason mentions soulbound: {msg}"
    );
    println!("[nft] eth_call soulbound: transferFrom simulation rejected with '{msg}'");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// M2-F2 / cycle-1 FU-1 — mempool over-admission regression. A second `openStream` whose deposit
// would lock the same sender balance the first already committed must be REJECTED synchronously at
// `eth_sendRawTransaction`, NOT accepted (returning a tx hash to the wallet) and then silently
// dropped by the runtime's fail-closed balance check at block time. Pre-fix, the submit gate
// compared each deposit against the full live balance in isolation, so N full-balance opens all
// got "accepted" and all but the first vanished with only a WARN log and no receipt.
// =============================================================================================
#[tokio::test]
async fn second_full_balance_open_rejected_at_admission() {
    let addr: SocketAddr = "127.0.0.1:18559".parse().unwrap();
    // Genesis well in the past so the dev account holds a sizable spendable balance from emission.
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS; // ~50 UBI accrued
    let (chain, handle) = boot(addr, genesis).await;

    let dev = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
    let recipient_a = address!("00000000000000000000000000000000000000a1");
    let recipient_b = address!("00000000000000000000000000000000000000b2");

    // Each open locks ~the entire live spendable balance as its deposit, so two cannot both be
    // funded. Emission may add a few base units before mining, but it never doubles the balance, so
    // the first open stays affordable while a second full-balance open never can be.
    let bal =
        hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([dev, "latest"])).await["result"]);
    assert!(bal > 0, "dev account must hold spendable balance to lock");
    let deposit = bal;

    // First open (nonce 0): the sole pending commitment, fits the balance → accepted.
    let open_a = openStreamCall {
        to: recipient_a,
        ratePerSec: U256::from(1u128),
        deposit: U256::from(deposit),
    }
    .abi_encode();
    let raw_a = sign_tx(STREAM_HUB, 0, open_a, 0, DEVNET_CHAIN_ID);
    let raw_a_hex = format!("0x{}", hex::encode(&raw_a));
    let send_a = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_a_hex])).await;
    let hash_a = send_a["result"]
        .as_str()
        .unwrap_or_else(|| panic!("first full-balance openStream must be accepted: {send_a}"))
        .to_string();
    println!("[mempool] first open accepted: {hash_a}");

    // Second open (nonce 1, so it clears the pending-nonce gate): same sender, another full-balance
    // deposit. The first open's deposit is already committed in the mempool, so the cumulative check
    // sees live_balance < pending_committed + this_deposit and must REJECT at admission.
    let open_b = openStreamCall {
        to: recipient_b,
        ratePerSec: U256::from(1u128),
        deposit: U256::from(deposit),
    }
    .abi_encode();
    let raw_b = sign_tx(STREAM_HUB, 0, open_b, 1, DEVNET_CHAIN_ID);
    let raw_b_hex = format!("0x{}", hex::encode(&raw_b));
    let send_b = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_b_hex])).await;
    assert!(
        send_b.get("result").is_none() && send_b.get("error").is_some(),
        "second full-balance openStream must be REJECTED at admission, not accepted: {send_b}"
    );
    let err_msg = send_b["error"]["message"].as_str().unwrap_or("");
    assert!(
        err_msg.contains("insufficient") && err_msg.contains("pending"),
        "rejection must cite the cumulative pending commitment, got: {err_msg}"
    );
    println!("[mempool] second open rejected at admission: {err_msg}");

    // Mine: exactly the first open lands. Pre-fix this asserted-out because BOTH opens were admitted
    // and the runtime then dropped the second — here the second never entered the mempool at all.
    let block = chain.produce_block(now_secs());
    assert_eq!(
        block.txs.len(),
        1,
        "exactly one open mined (the first); the over-committed second was never admitted"
    );

    // The dev account is left with exactly one outgoing stream — no orphaned second deposit lock.
    let receipt_a =
        rpc(addr, "eth_getTransactionReceipt", serde_json::json!([hash_a])).await;
    assert!(
        receipt_a["result"]["logs"]
            .as_array()
            .map_or(0, |l| l.len())
            >= 1,
        "first open has a receipt with logs (it actually mined): {receipt_a}"
    );
    let (outgoing, _incoming) = chain.streams_of(&DEV_ADDR.into_array());
    assert_eq!(
        outgoing.len(),
        1,
        "dev has exactly one outgoing stream, not a second orphaned deposit lock"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// Minimal standard base64 decoder (keeps the test self-contained; mirrors the crate's `base64` use).
fn b64_decode(s: &str) -> Vec<u8> {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    STANDARD.decode(s).expect("valid base64")
}
