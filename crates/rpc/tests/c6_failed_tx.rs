//! Cycle-6 regression: a tx whose lifecycle op FAILS at block time must be MINED as a FAILED tx
//! (EVM-correct: charge the fee, consume the nonce, emit a `status: 0x0` receipt carrying the decoded
//! failure reason), never SILENTLY DROPPED.
//!
//! ## The bug this guards against
//! `eth_sendRawTransaction` accepts a well-formed hub tx (returns a hash → the wallet shows it
//! pending), but at `produce_block` the op fails validation (e.g. `vouch` to an address with no open
//! registration → "vouchee has no open registration"). The old code rolled back the fee AND the nonce
//! and `continue`d — the tx was never mined, never got a receipt, and the sender nonce was NOT
//! consumed. Result: the wallet polls forever (perpetual pending) AND its local nonce advanced while
//! the chain nonce did not → the NEXT tx is rejected "nonce too high", a permanent cascade.
//!
//! ## The fixed contract (every assertion below maps to it)
//!   * a failing op is **mined as a FAILED tx**: present in the block, `status: 0x0`, the decoded
//!     reason surfaced in `eth_getTransactionReceipt`, `ubi_getTransaction`, and `ubi_getBlock`;
//!   * the **fee is charged** (it lands in the TREASURY — the node did work);
//!   * the **nonce is consumed** (a SECOND tx from that sender at the next nonce then SUCCEEDS — no
//!     nonce gap, proving the cascade is gone);
//!   * **no op state change** is applied (a failed `vouch` creates NO vouch edge);
//!   * a failing CONTRACT op (invoke a non-existent contract) is likewise mined-failed;
//!   * a sender who cannot even afford the fee is **rejected at submit** (no pending) — the only case
//!     that must NOT be mined.
//!
//! All deterministic (I2): the same mempool at the same timestamp produces the same FAILED tx + reason
//! on every node.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::contracts::{invokeContractCall, CONTRACT_HUB};
use ubi2_rpc::humanity::{vouchCall, HUMANITY_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, MockInterpreter, MockOracle, EMISSION_PERIOD_SECS, TREASURY, UBI};

/// Well-known PUBLIC devnet keys (Hardhat/Anvil accounts). NOT SECRETS.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// A second funded Verified human (acct #4) — the sender of the failing CONTRACT-op tx.
const SENDER2_KEY: [u8; 32] =
    hex32("47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a");
const SENDER2: AlloyAddr = address!("15d34AAf54267DB7D7c367839AAf71A00a2C6A65");

/// A bystander address that has NO open registration — vouching for it must fail at block time.
const NON_APPLICANT: AlloyAddr = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");

/// A poor, never-funded sender (acct #6) — cannot afford even the fee, so submit must reject it.
const POOR_KEY: [u8; 32] =
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
fn hex_u64(v: &serde_json::Value) -> u64 {
    let s = v.as_str().expect("hex string");
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex quantity")
}
fn hex_u128(v: &serde_json::Value) -> u128 {
    let s = v.as_str().expect("hex string");
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex quantity")
}

/// Send a signed raw tx; assert it was accepted (returns a tx-hash string).
async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send should be accepted: {resp}"))
        .to_string()
}

/// Send a signed raw tx; assert it was REJECTED at submit (returns the error message).
async fn send_err(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        resp["result"].is_null(),
        "expected submit rejection, got accepted: {resp}"
    );
    resp["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("expected an error message: {resp}"))
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

/// Boot a Chain with two funded Verified humans (DEV_ADDR + SENDER2) so each can pay hub-op fees, and
/// the default confident oracle/interpreter. `genesis` drives emission; we pick it ~1000h in the past
/// so both accounts have a large spendable balance.
async fn boot(addr: SocketAddr, genesis: u64) -> (Chain, jsonrpsee::server::ServerHandle) {
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis)
        .with_oracle(Arc::new(MockOracle::default()))
        .with_interpreter(Arc::new(MockInterpreter::default()));
    for a in [DEV_ADDR, SENDER2] {
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
    let handle = serve(addr, chain.clone()).await.expect("serve");
    (chain, handle)
}

/// The decoded failure reason a FAILED tx must carry, read from the three surfaces:
/// `eth_getTransactionReceipt.revertReason`, `ubi_getTransaction.result.reason`, and the matching
/// `ubi_getBlock` tx. Asserts all three agree and returns the reason string.
async fn assert_failed_reason(addr: SocketAddr, tx_hash: &str, block_number: u64) -> String {
    // 1) eth_getTransactionReceipt — EVM `status: 0x0` + a reason field for the explorer.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await;
    let r = &receipt["result"];
    assert!(!r.is_null(), "FAILED tx must have a receipt (not pending)");
    assert_eq!(
        r["status"].as_str(),
        Some("0x0"),
        "FAILED tx receipt status must be 0x0: {receipt}"
    );
    let reason = r["revertReason"]
        .as_str()
        .unwrap_or_else(|| panic!("receipt must carry a revertReason: {receipt}"))
        .to_string();
    assert!(!reason.is_empty(), "reason must be non-empty");

    // 2) eth_getTransactionByHash — the tx is mined (has a block), not pending.
    let by_hash = rpc(
        addr,
        "eth_getTransactionByHash",
        serde_json::json!([tx_hash]),
    )
    .await;
    assert!(
        !by_hash["result"].is_null(),
        "FAILED tx must be retrievable by hash (mined, not dropped)"
    );
    assert_eq!(
        hex_u64(&by_hash["result"]["blockNumber"]),
        block_number,
        "tx must be in the produced block"
    );

    // 3) ubi_getTransaction — explorer shape: status + the same reason.
    let decoded = rpc(addr, "ubi_getTransaction", serde_json::json!([tx_hash])).await;
    let d = &decoded["result"];
    assert_eq!(
        d["status"].as_str(),
        Some("0x0"),
        "ubi_getTransaction status must be 0x0: {decoded}"
    );
    assert_eq!(
        d["result"]["reason"].as_str(),
        Some(reason.as_str()),
        "ubi_getTransaction.result.reason must match the receipt reason: {decoded}"
    );

    // 4) ubi_getBlock — the same tx, decoded, carries the same failed status + reason.
    let block = rpc(
        addr,
        "ubi_getBlock",
        serde_json::json!([format!("0x{block_number:x}")]),
    )
    .await;
    let txs = block["result"]["transactions"]
        .as_array()
        .expect("block has transactions array");
    let found = txs
        .iter()
        .find(|t| t["hash"].as_str() == Some(tx_hash))
        .unwrap_or_else(|| panic!("FAILED tx must appear in ubi_getBlock: {block}"));
    assert_eq!(
        found["status"].as_str(),
        Some("0x0"),
        "ubi_getBlock tx status must be 0x0"
    );

    reason
}

/// CORE REGRESSION: a `vouch` to a non-applicant is MINED as FAILED (status 0x0 + reason), the fee is
/// charged to the TREASURY, the sender nonce is consumed, NO vouch edge is created, and a SECOND tx
/// from that sender at the next nonce then SUCCEEDS — proving no nonce gap / no perpetual pending.
#[tokio::test]
async fn failing_vouch_is_mined_failed_nonce_consumed_no_pending() {
    let addr: SocketAddr = "127.0.0.1:39751".parse().unwrap();
    // Genesis 1000h in the past so DEV_ADDR has ~1000 UBI to pay fees with.
    let genesis = now_secs() - 1000 * EMISSION_PERIOD_SECS;
    let (chain, _handle) = boot(addr, genesis).await;

    let nonce0 = hex_u64(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([format!("0x{}", hex::encode(DEV_ADDR.as_slice())), "latest"]),
        )
        .await["result"],
    );
    assert_eq!(nonce0, 0, "fresh sender starts at nonce 0");

    let treasury_hex = format!("0x{}", hex::encode(TREASURY.as_slice()));
    let treasury_pre = hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([treasury_hex, "latest"]),
        )
        .await["result"],
    );

    // 1) vouch for a non-applicant — accepted at submit (well-formed), MUST fail at block time.
    let vouch_data = vouchCall {
        vouchee: NON_APPLICANT,
    }
    .abi_encode();
    let tx_hash = send_ok(addr, sign_tx(&DEV_PRIVKEY, HUMANITY_HUB, 0, vouch_data, 0)).await;

    let block = chain.produce_block(now_secs());

    // The FAILED tx is mined (status 0x0) with a decoded reason on every surface.
    let reason = assert_failed_reason(addr, &tx_hash, block.number).await;
    assert!(
        reason.contains("registration") || reason.contains("vouchee"),
        "reason should explain the vouch failure, got: {reason}"
    );

    // The nonce was consumed (chain nonce advanced 0 → 1) — no rollback, no nonce gap.
    let nonce1 = hex_u64(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([format!("0x{}", hex::encode(DEV_ADDR.as_slice())), "latest"]),
        )
        .await["result"],
    );
    assert_eq!(nonce1, 1, "FAILED tx must CONSUME the sender nonce");

    // The fee landed in the TREASURY (EVM charges gas on revert; the node did work).
    let treasury_post = hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([treasury_hex, "latest"]),
        )
        .await["result"],
    );
    assert!(
        treasury_post > treasury_pre,
        "the FAILED tx's fee must be charged to the TREASURY (was {treasury_pre}, now {treasury_post})"
    );

    // NO op state change: the non-applicant got NO vouch edge.
    let vouches = rpc(
        addr,
        "ubi_getVouches",
        serde_json::json!([format!("0x{}", hex::encode(NON_APPLICANT.as_slice()))]),
    )
    .await;
    let incoming = vouches["result"]["incoming"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(
        incoming.is_empty(),
        "a FAILED vouch must create NO vouch edge: {vouches}"
    );

    // 2) THE CASCADE IS GONE: a SECOND tx from the SAME sender at the NEXT nonce (1) succeeds.
    // Pre-fix, the wallet's nonce had advanced to 1 but the chain's was still 0, so this would be
    // rejected "nonce too high". Now the chain nonce is 1, so it is accepted and mined.
    let transfer_hash = send_ok(addr, sign_tx(&DEV_PRIVKEY, NON_APPLICANT, UBI, vec![], 1)).await;
    let block2 = chain.produce_block(now_secs());
    let r2 = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([transfer_hash]),
    )
    .await;
    assert_eq!(
        r2["result"]["status"].as_str(),
        Some("0x1"),
        "the follow-up tx at the next nonce must SUCCEED (no nonce gap): {r2}"
    );
    assert_eq!(
        hex_u64(&r2["result"]["blockNumber"]),
        block2.number,
        "follow-up tx mined in the next block"
    );
}

/// A failing CONTRACT op (invoke a non-existent contract) is likewise mined-failed with status 0x0 +
/// a reason, fee charged, nonce consumed — and a follow-up tx from that sender then succeeds.
#[tokio::test]
async fn failing_contract_invoke_is_mined_failed() {
    let addr: SocketAddr = "127.0.0.1:39752".parse().unwrap();
    let genesis = now_secs() - 1000 * EMISSION_PERIOD_SECS;
    let (chain, _handle) = boot(addr, genesis).await;

    // Invoke a contract id that was never deployed → "no such contract" at block time.
    let invoke_data = invokeContractCall {
        id: U256::from(999u64),
        triggerRef: [7u8; 32].into(),
    }
    .abi_encode();
    let tx_hash = send_ok(addr, sign_tx(&SENDER2_KEY, CONTRACT_HUB, 0, invoke_data, 0)).await;

    let block = chain.produce_block(now_secs());
    let reason = assert_failed_reason(addr, &tx_hash, block.number).await;
    assert!(
        reason.contains("contract"),
        "reason should explain the missing contract, got: {reason}"
    );

    // Nonce consumed → a follow-up transfer at nonce 1 succeeds (no cascade).
    let follow = send_ok(addr, sign_tx(&SENDER2_KEY, DEV_ADDR, UBI, vec![], 1)).await;
    let block2 = chain.produce_block(now_secs());
    let r2 = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([follow]),
    )
    .await;
    assert_eq!(
        r2["result"]["status"].as_str(),
        Some("0x1"),
        "follow-up tx after a FAILED contract op must succeed: {r2}"
    );
    assert_eq!(hex_u64(&r2["result"]["blockNumber"]), block2.number);
}

/// The ONLY case that must NOT be mined: a sender who cannot even afford the fee is REJECTED AT SUBMIT
/// (so the wallet shows an error synchronously), never accepted into a perpetual-pending state.
#[tokio::test]
async fn sender_who_cannot_afford_fee_is_rejected_at_submit() {
    let addr: SocketAddr = "127.0.0.1:39753".parse().unwrap();
    let genesis = now_secs() - 1000 * EMISSION_PERIOD_SECS;
    let (_chain, _handle) = boot(addr, genesis).await;

    // POOR is never seeded → zero balance, cannot pay the humanity-op fee. A vouch is a fee-bearing
    // op (GAS_HUMANITY), so submit must reject it for insufficient balance.
    let vouch_data = vouchCall {
        vouchee: NON_APPLICANT,
    }
    .abi_encode();
    let err = send_err(addr, sign_tx(&POOR_KEY, HUMANITY_HUB, 0, vouch_data, 0)).await;
    assert!(
        err.contains("insufficient") || err.contains("balance") || err.contains("fee"),
        "a sender who cannot afford the fee must be rejected at submit with a clear error, got: {err}"
    );
}
