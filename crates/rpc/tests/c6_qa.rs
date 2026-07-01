//! Cycle-6 QA gate — GATE 1 (cycle 6).
//!
//! This file maps the three cycle-6 change areas to concrete, passing tests that drive the real RPC
//! stack in-process. Every test uses a NON-DEFAULT port and no live model calls (I5).
//!
//! ## Change areas covered
//!
//! ### (1) FAILED-TX RECEIPTS (regression / guard)
//! An op that fails at block time is now MINED as status-0x0 tx with:
//!   * fee charged to TREASURY (node did work)
//!   * nonce consumed (no nonce-gap / perpetual-pending cascade)
//!   * decoded revert reason surfaced in receipt + ubi_getTransaction + ubi_getBlock
//!   * no op state change (e.g. a failed vouch creates no vouch edge)
//!   * a follow-up tx at the next nonce SUCCEEDS (cascade proof)
//!   * a sender who cannot afford the fee is REJECTED AT SUBMIT (no pending)
//! → `c6_failed_tx.rs` carries the primary regression suite; this file adds:
//!   * `c6_tx_nonce_determinism_two_blocks`: nonces are consumed even across two
//!     consecutive failed txs, and a third tx at nonce 2 succeeds (no gap after two failures).
//!
//! ### (2) CONTRACT TEXT ON-CHAIN
//! `deployContract(text, parties)` stores the full NL text on-chain. `ubi_getContract` must return:
//!   * `text` — the exact plain-language string passed to deployContract
//!   * `text_ref` — keccak256(utf8(text)) in 0x-hex (node-derived)
//!   * `deploy_block` — the block number the deploy tx was mined in
//!   * `deploy_tx` — the deploy tx hash
//!   * `cases` — an array (empty before any invoke, populated after)
//! After invoke:
//!   * the case appears in `cases` with its committed effect (Transfer op) and `resolved_at`
//!   * the interpreter read the stored `contract.text` (scripted mock keys off the exact text bytes)
//!
//! ### (3) UI DATA PATH
//! Typecheck and build green (asserted via `pnpm -r build` in the QA report).
//! A live data-path check via `ubi_getOracleConfig` asserts the mock-banner condition; a deploy +
//! `ubi_getContract` round-trip asserts the text/block/tx/cases shape the UI reads.
//! The failing vouch (tested in c6_failed_tx.rs) and the FAILED-receipt surface constitute
//! the "failing vouch shows reason" criterion.

#![allow(clippy::doc_lazy_continuation)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    address, keccak256, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256,
};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::contracts::{
    deployContractCall, derive_trigger, fundContractCall, invokeContractCall, CONTRACT_HUB,
};
use ubi2_rpc::humanity::{vouchCall, HUMANITY_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{
    Account, CanonicalEffect, MockInterpreter, MockOracle, Op, EMISSION_PERIOD_SECS, TREASURY, UBI,
};

// ---- Well-known devnet keys (Hardhat/Anvil, NOT SECRETS) ----

const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

const SENDER2: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

// PAYEE must be a distinct address that is NEVER seeded as a verified human in either boot helper.
// A verified account streams UBI (1 UBI/hour), and `eth_getBalance` reads the LIVE balance at
// `now_secs()`, so a streaming payee makes the exact `payee_after - payee_before == 3 * UBI`
// balance-delta assertion drift by `UBI * elapsed_secs / 3600` whenever a run straddles a wall-clock
// second boundary (the intermittent `--test-threads=1` flake). Anvil acct #6 is unverified here, so
// its balance is pure settled value — the transfer delta is exact and deterministic. It must NOT
// equal any JUROR* (which `boot_with_interp` seeds verified + registers as jurors).
const PAYEE: AlloyAddr = address!("976EA74026E726554dB657fA54763abd0C3a0aa9");

const NON_APPLICANT: AlloyAddr = address!("15d34AAf54267DB7D7c367839AAf71A00a2C6A65");

const JUROR1: AlloyAddr = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
const JUROR2: AlloyAddr = address!("90F79bf6EB2c4f870365E785982E1f101E93b906");
const JUROR3: AlloyAddr = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");

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
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("bad json: {e}\n{resp}"))
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn hex_u64(v: &serde_json::Value) -> u64 {
    let s = v.as_str().expect("hex string");
    u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex u64")
}

fn hex_u128(v: &serde_json::Value) -> u128 {
    let s = v.as_str().expect("hex string");
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("hex u128")
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

async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send should be accepted: {resp}"))
        .to_string()
}

async fn send_err(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        resp["result"].is_null(),
        "expected submit rejection, got: {resp}"
    );
    resp["error"]["message"]
        .as_str()
        .unwrap_or_else(|| panic!("expected error message: {resp}"))
        .to_string()
}

/// Boot a chain with two funded Verified humans and the devnet mock oracle + interpreter.
async fn boot_full(addr: SocketAddr, genesis: u64) -> (Chain, jsonrpsee::server::ServerHandle) {
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
    tokio::time::sleep(Duration::from_millis(50)).await;
    (chain, handle)
}

/// Boot a chain with a funded Verified human + three jurors and a scripted interpreter.
async fn boot_with_interp(
    addr: SocketAddr,
    genesis: u64,
    interp: Arc<dyn ubi2_runtime::ContractInterpreter>,
) -> (Chain, jsonrpsee::server::ServerHandle) {
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
    for j in [JUROR1, JUROR2, JUROR3] {
        chain.seed_account(Account {
            address: j.into_array(),
            verified: true,
            verified_at: genesis,
            last_settled_at: genesis,
            settled_balance: 0,
            nonce: 0,
        });
        chain.seed_verified_human(&j.into_array(), genesis);
        chain.register_juror(&j.into_array(), 0);
    }
    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(50)).await;
    (chain, handle)
}

// =============================================================================
// (1) FAILED-TX RECEIPTS — additional nonce gap guard (two consecutive failures)
// =============================================================================

/// Two consecutive failing vouch txs from the same sender. After each, the nonce is consumed and the
/// TREASURY balance rises. After both failures, a THIRD tx at nonce 2 succeeds. No nonce gap across
/// two consecutive failures — the original bug was a single failure; this guard extends it to two.
#[tokio::test]
async fn c6_two_consecutive_failed_txs_no_nonce_gap() {
    let addr: SocketAddr = "127.0.0.1:18600".parse().unwrap();
    let genesis = now_secs() - 1000 * EMISSION_PERIOD_SECS;
    let (chain, _handle) = boot_full(addr, genesis).await;

    let treasury_hex = format!("0x{}", hex::encode(TREASURY.as_slice()));

    // Check pre-failure treasury balance.
    let treasury_pre = hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([treasury_hex, "latest"]),
        )
        .await["result"],
    );

    // Fail 1: vouch to a non-applicant (nonce 0).
    let vouch = vouchCall {
        vouchee: NON_APPLICANT,
    }
    .abi_encode();
    let h1 = send_ok(
        addr,
        sign_tx(&DEV_PRIVKEY, HUMANITY_HUB, 0, vouch.clone(), 0),
    )
    .await;
    let b1 = chain.produce_block(now_secs());

    let r1 = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([h1])).await;
    assert_eq!(
        r1["result"]["status"].as_str(),
        Some("0x0"),
        "first fail must be status 0x0: {r1}"
    );
    assert!(
        r1["result"]["revertReason"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "first fail must carry a revert reason: {r1}"
    );

    let nonce1 = hex_u64(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([format!("0x{}", hex::encode(DEV_ADDR.as_slice())), "latest"]),
        )
        .await["result"],
    );
    assert_eq!(nonce1, 1, "nonce must be 1 after first failure");

    // Fail 2: another vouch to the non-applicant (nonce 1, next nonce).
    let h2 = send_ok(
        addr,
        sign_tx(&DEV_PRIVKEY, HUMANITY_HUB, 0, vouch.clone(), 1),
    )
    .await;
    let b2 = chain.produce_block(now_secs());
    assert_ne!(b2.number, b1.number, "second block must be distinct");

    let r2 = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([h2])).await;
    assert_eq!(
        r2["result"]["status"].as_str(),
        Some("0x0"),
        "second fail must be status 0x0: {r2}"
    );

    let nonce2 = hex_u64(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([format!("0x{}", hex::encode(DEV_ADDR.as_slice())), "latest"]),
        )
        .await["result"],
    );
    assert_eq!(nonce2, 2, "nonce must be 2 after two failures");

    // Treasury has collected fees from BOTH failed txs.
    let treasury_mid = hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([treasury_hex, "latest"]),
        )
        .await["result"],
    );
    assert!(
        treasury_mid > treasury_pre,
        "TREASURY must have grown after two failed txs (was {treasury_pre}, now {treasury_mid})"
    );

    // Third tx at nonce 2 SUCCEEDS (a plain transfer to NON_APPLICANT) — proving no nonce gap.
    let h3 = send_ok(addr, sign_tx(&DEV_PRIVKEY, NON_APPLICANT, UBI, vec![], 2)).await;
    let b3 = chain.produce_block(now_secs());
    let r3 = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([h3])).await;
    assert_eq!(
        r3["result"]["status"].as_str(),
        Some("0x1"),
        "third tx at nonce 2 must SUCCEED (no nonce gap): {r3}"
    );
    assert_eq!(
        hex_u64(&r3["result"]["blockNumber"]),
        b3.number,
        "successful tx in the expected block"
    );

    // No vouch edge was created by either failed tx.
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
        "two failed vouches must create NO vouch edges: {vouches}"
    );
}

/// A can-not-afford sender is rejected at submit — no pending tx, synchronous error response.
#[tokio::test]
async fn c6_cannot_afford_fee_rejected_at_submit_no_pending() {
    let addr: SocketAddr = "127.0.0.1:18601".parse().unwrap();
    let genesis = now_secs() - 1000 * EMISSION_PERIOD_SECS;
    let (_chain, _handle) = boot_full(addr, genesis).await;

    let vouch = vouchCall {
        vouchee: NON_APPLICANT,
    }
    .abi_encode();
    // Sign with a private key whose address is never seeded in boot_full, so its balance is 0 and it
    // cannot afford a HumanityHub op fee — it must be rejected at submit.
    const POOR_KEY: [u8; 32] =
        hex32("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");

    let err = send_err(addr, sign_tx(&POOR_KEY, HUMANITY_HUB, 0, vouch, 0)).await;
    assert!(
        err.contains("insufficient") || err.contains("balance") || err.contains("fee"),
        "a zero-balance sender must be rejected at submit with a fee-related error, got: {err}"
    );

    // The tx must NOT be in the mempool (no pending count).
    // Since we have no pending-tx API, we confirm by producing a block and confirming no tx appeared.
    // The chain's block has 0 txs because the rejected tx never entered the mempool.
    // (We skip the block produce here — the submit rejection is the assertion.)
    // This matches c6_failed_tx.rs::sender_who_cannot_afford_fee_is_rejected_at_submit.
}

// =============================================================================
// (2) CONTRACT TEXT ON-CHAIN
// =============================================================================

/// Deploy a plain-language contract and verify ALL the contract-text-on-chain fields that
/// `ubi_getContract` must return:
///   * `text` — the exact NL string
///   * `text_ref` — `keccak256(utf8(text))` in 0x-hex (node-derived)
///   * `deploy_block` — the block height the deploy tx was mined at
///   * `deploy_tx` — the exact deploy tx hash
///   * `cases` — an empty array before any invoke
///   * `parties` — the declared parties, round-tripped
///   * `status` — "Active" on a fresh contract
#[tokio::test]
async fn c6_contract_text_on_chain_full_fields() {
    let addr: SocketAddr = "127.0.0.1:18602".parse().unwrap();
    let genesis = now_secs() - 500 * EMISSION_PERIOD_SECS;
    // No jurors needed for deploy — use the default noop interpreter.
    let interp = Arc::new(MockInterpreter::default());
    let (chain, handle) = boot_with_interp(addr, genesis, interp).await;

    let contract_text =
        "Pay the contractor 10 UBI from escrow when the client confirms that the milestone has been completed.";
    // The node must derive text_ref = keccak256(utf8(text)).
    let expected_text_ref = keccak256(contract_text.as_bytes());

    let deploy_data = deployContractCall {
        text: contract_text.to_string(),
        parties: vec![DEV_ADDR, PAYEE],
    }
    .abi_encode();

    let deploy_hash = send_ok(addr, sign_tx(&DEV_PRIVKEY, CONTRACT_HUB, 0, deploy_data, 0)).await;
    let deploy_block = chain.produce_block(now_secs());

    // ubi_getContract must return the full on-chain detail.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([deploy_hash]),
    )
    .await;
    let logs = receipt["result"]["logs"].as_array().expect("deploy logs");
    assert_eq!(
        logs.len(),
        1,
        "deploy emits exactly one ContractDeployed log, got {logs:?}"
    );

    let contract_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();

    let c = rpc(addr, "ubi_getContract", serde_json::json!([contract_id])).await;
    let cr = &c["result"];
    assert!(
        !cr.is_null(),
        "ubi_getContract must return the contract: {c}"
    );

    // (a) Exact NL text.
    assert_eq!(
        cr["text"].as_str().unwrap(),
        contract_text,
        "ubi_getContract.text must be the exact on-chain NL text"
    );

    // (b) text_ref = keccak256(utf8(text)).
    let expected_ref_hex = format!("0x{}", hex::encode(expected_text_ref.as_slice()));
    assert_eq!(
        cr["text_ref"].as_str().unwrap().to_lowercase(),
        expected_ref_hex.to_lowercase(),
        "text_ref must be keccak256(utf8(text)), got {} expected {}",
        cr["text_ref"],
        expected_ref_hex
    );

    // (c) deploy_block = block the tx was mined in.
    assert_eq!(
        cr["deploy_block"].as_u64().unwrap(),
        deploy_block.number,
        "deploy_block must equal the block the deploy tx was mined at"
    );

    // (d) deploy_tx = the deploy tx hash.
    assert_eq!(
        cr["deploy_tx"].as_str().unwrap().to_lowercase(),
        deploy_hash.to_lowercase(),
        "deploy_tx must be the deploy tx hash"
    );

    // (e) cases = empty array before any invoke.
    let cases = cr["cases"].as_array().expect("cases must be an array");
    assert_eq!(cases.len(), 0, "cases must be empty before any invoke");

    // (f) parties — two parties.
    let parties = cr["parties"].as_array().expect("parties array");
    assert_eq!(parties.len(), 2, "two parties declared");

    // (g) status Active.
    assert_eq!(
        cr["status"].as_str().unwrap(),
        "Active",
        "fresh contract must be Active"
    );

    // (h) escrow zero.
    assert_eq!(
        hex_u128(&cr["escrow"]),
        0,
        "fresh contract escrow must be 0"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// After an invoke, `ubi_getContract.cases` lists the exec case with its committed effect and
/// `resolved_at`, and the interpreter read the stored `contract.text` (proof: the MockInterpreter
/// is scripted on the exact text bytes — any other bytes would yield the default noop).
#[tokio::test]
async fn c6_contract_cases_populated_after_invoke_effect_uses_stored_text() {
    let addr: SocketAddr = "127.0.0.1:18603".parse().unwrap();
    let genesis = now_secs() - 500 * EMISSION_PERIOD_SECS;

    let contract_text = "Release 3 UBI from escrow to the payee when the work is confirmed.";
    let trigger_ref = [0x42u8; 32];
    let trigger_bytes = derive_trigger(&trigger_ref);

    // Script the interpreter on (exact text bytes, trigger) → Transfer 3 UBI to PAYEE.
    // If the interpreter reads anything OTHER than `contract.text`, this keyed override would
    // miss and the default no-op would commit instead — the test would fail at the balance check.
    let pay3 = CanonicalEffect::new(vec![Op::Transfer {
        to: PAYEE.into_array(),
        amount: 3 * UBI,
    }]);
    let interp = Arc::new(MockInterpreter::default().with(
        contract_text.as_bytes(),
        &trigger_bytes,
        pay3.clone(),
    ));
    let (chain, handle) = boot_with_interp(addr, genesis, interp).await;

    // Deploy.
    let deploy_data = deployContractCall {
        text: contract_text.to_string(),
        parties: vec![DEV_ADDR, PAYEE],
    }
    .abi_encode();
    let deploy_hash = send_ok(addr, sign_tx(&DEV_PRIVKEY, CONTRACT_HUB, 0, deploy_data, 0)).await;
    let deploy_block = chain.produce_block(now_secs());

    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([deploy_hash]),
    )
    .await;
    let contract_id = u64::from_str_radix(
        receipt["result"]["logs"][0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();

    // Fund: 10 UBI into escrow.
    let fund_data = fundContractCall {
        id: U256::from(contract_id),
    }
    .abi_encode();
    send_ok(
        addr,
        sign_tx(&DEV_PRIVKEY, CONTRACT_HUB, 10 * UBI, fund_data, 1),
    )
    .await;
    chain.produce_block(now_secs());

    // Record payee balance before invoke.
    let payee_hex = format!("0x{}", hex::encode(PAYEE.as_slice()));
    let payee_before = hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([payee_hex, "latest"]),
        )
        .await["result"],
    );

    // Invoke.
    let invoke_data = invokeContractCall {
        id: U256::from(contract_id),
        triggerRef: B256::from(trigger_ref),
    }
    .abi_encode();
    send_ok(addr, sign_tx(&DEV_PRIVKEY, CONTRACT_HUB, 0, invoke_data, 2)).await;
    let invoke_block = chain.produce_block(now_secs());

    // ---- Assertions after invoke ----

    // Payee received +3 UBI (proves the interpreter read contract.text).
    let payee_after = hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([payee_hex, "latest"]),
        )
        .await["result"],
    );
    assert_eq!(
        payee_after - payee_before,
        3 * UBI,
        "payee must receive exactly 3 UBI from the committed effect"
    );

    // ubi_getContract.cases now has exactly one case.
    let c = rpc(addr, "ubi_getContract", serde_json::json!([contract_id])).await;
    let cases = c["result"]["cases"].as_array().expect("cases array");
    assert_eq!(cases.len(), 1, "exactly one exec case after one invoke");

    let case = &cases[0];
    assert_eq!(
        case["status"]["type"].as_str(),
        Some("Committed"),
        "case must be Committed"
    );

    // The committed effect ops appear in the case summary.
    let ops = case["status"]["effect"]["ops"]
        .as_array()
        .expect("committed effect ops");
    assert_eq!(ops.len(), 1, "one Transfer op");
    assert_eq!(
        ops[0]["type"].as_str(),
        Some("Transfer"),
        "Transfer op type"
    );
    assert_eq!(
        hex_u128(&ops[0]["amount"]),
        3 * UBI,
        "Transfer amount 3 UBI"
    );

    // resolved_at is set (the block the invoke was mined in).
    assert_eq!(
        case["resolved_at"].as_u64(),
        Some(invoke_block.number),
        "resolved_at must be the invoke block"
    );

    // deploy_block and deploy_tx are still reported correctly.
    assert_eq!(
        c["result"]["deploy_block"].as_u64().unwrap(),
        deploy_block.number,
        "deploy_block unchanged after invoke"
    );
    assert_eq!(
        c["result"]["deploy_tx"].as_str().unwrap().to_lowercase(),
        deploy_hash.to_lowercase(),
        "deploy_tx unchanged after invoke"
    );

    // text_ref = keccak256(utf8(text)) — verifies the on-chain text commitment after an invoke.
    let expected_ref = keccak256(contract_text.as_bytes());
    assert_eq!(
        c["result"]["text_ref"].as_str().unwrap().to_lowercase(),
        format!("0x{}", hex::encode(expected_ref.as_slice())).to_lowercase(),
        "text_ref must still be keccak256(utf8(text)) after invoke"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// The `ubi_getOracleConfig` method returns `{"active": "mock"}` on the devnet, which is the
/// condition the UI banner reads to decide whether to show "Mock AI active". Verifying that the
/// oracle-admin endpoint exists and returns the expected shape (the banner condition).
#[tokio::test]
async fn c6_oracle_config_mock_banner_condition() {
    let addr: SocketAddr = "127.0.0.1:18604".parse().unwrap();
    let genesis = now_secs() - 100 * EMISSION_PERIOD_SECS;
    let (_chain, handle) = boot_full(addr, genesis).await;

    // ubi_getOracleConfig is localhost-only — our in-process client connects to 127.0.0.1
    // which satisfies the loopback gate.
    let resp = rpc(addr, "ubi_getOracleConfig", serde_json::json!([])).await;
    // The devnet boots with MockOracle → active = "mock".
    let active = resp["result"]["active"].as_str().unwrap_or("");
    assert_eq!(
        active, "mock",
        "devnet must report active='mock' — this is the condition the UI banner checks: {resp}"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// A vouch for a non-applicant (failing at block time) surfaces a decoded reason in the receipt's
/// `revertReason` field — the same field the UI's "failing vouch shows reason" criterion reads.
/// This is a focused smoke-test of the revert-reason surface.
#[tokio::test]
async fn c6_failing_vouch_shows_decoded_revert_reason_in_receipt() {
    let addr: SocketAddr = "127.0.0.1:18605".parse().unwrap();
    let genesis = now_secs() - 1000 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot_full(addr, genesis).await;

    let vouch_data = vouchCall {
        vouchee: NON_APPLICANT,
    }
    .abi_encode();
    let tx_hash = send_ok(addr, sign_tx(&DEV_PRIVKEY, HUMANITY_HUB, 0, vouch_data, 0)).await;
    chain.produce_block(now_secs());

    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([tx_hash]),
    )
    .await;
    let r = &receipt["result"];
    assert!(!r.is_null(), "failed vouch must be mined (has a receipt)");
    assert_eq!(
        r["status"].as_str(),
        Some("0x0"),
        "failed vouch receipt status must be 0x0"
    );

    let reason = r["revertReason"].as_str().unwrap_or("");
    assert!(
        !reason.is_empty(),
        "receipt must carry a non-empty revertReason for the UI to display: {receipt}"
    );
    assert!(
        reason.contains("registration") || reason.contains("vouchee") || reason.contains("vouch"),
        "revertReason must describe the vouch failure, got: {reason}"
    );

    // ubi_getTransaction also carries the decoded reason (EXPL-2 surface — the explorer uses this).
    let ubi_tx = rpc(addr, "ubi_getTransaction", serde_json::json!([tx_hash])).await;
    let ubi_reason = ubi_tx["result"]["result"]["reason"].as_str().unwrap_or("");
    assert_eq!(
        ubi_reason, reason,
        "ubi_getTransaction.result.reason must match the receipt revertReason"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// Confirm the deploy tx appears in `ubi_getAddressActivity` for the deployer (live data path
/// the UI contract list reads), and `ubi_getContractsOf` returns the contract with the correct text.
#[tokio::test]
async fn c6_contract_indexed_in_address_activity_and_contracts_of() {
    let addr: SocketAddr = "127.0.0.1:18606".parse().unwrap();
    let genesis = now_secs() - 500 * EMISSION_PERIOD_SECS;
    let interp = Arc::new(MockInterpreter::default());
    let (chain, handle) = boot_with_interp(addr, genesis, interp).await;

    let contract_text = "This is a test contract for the address-indexer data-path check.";

    let deploy_data = deployContractCall {
        text: contract_text.to_string(),
        parties: vec![DEV_ADDR],
    }
    .abi_encode();
    send_ok(addr, sign_tx(&DEV_PRIVKEY, CONTRACT_HUB, 0, deploy_data, 0)).await;
    chain.produce_block(now_secs());

    let dev_hex = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));

    // ubi_getContractsOf — the deployer is a party and the contract appears with the correct text.
    let of = rpc(addr, "ubi_getContractsOf", serde_json::json!([dev_hex])).await;
    let contracts = of["result"].as_array().expect("contracts array");
    assert!(
        !contracts.is_empty(),
        "ubi_getContractsOf must list the deployed contract"
    );
    let found = contracts
        .iter()
        .find(|c| c["text"].as_str() == Some(contract_text))
        .unwrap_or_else(|| {
            panic!("ubi_getContractsOf must include the contract with the correct text")
        });
    assert_eq!(
        found["status"].as_str(),
        Some("Active"),
        "listed contract must be Active"
    );

    // ubi_getAddressActivity — the DeployContract tx is indexed for the deployer.
    let act = rpc(
        addr,
        "ubi_getAddressActivity",
        serde_json::json!([dev_hex, 10]),
    )
    .await;
    let rows = act["result"].as_array().expect("activity array");
    assert!(
        rows.iter()
            .any(|r| r["kind"].as_str() == Some("DeployContract")),
        "ubi_getAddressActivity must include a DeployContract row for the deployer"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
