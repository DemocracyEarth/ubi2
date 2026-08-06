//! Proof-of-Humanity soulbound NFT acceptance test (branch `feat/poh-nft-branding`).
//!
//! Boots the real [`ubi2_rpc::serve`] HTTP+WS JSON-RPC server in-process and drives the HumanityHub
//! (`0x…5048`) as an ERC-721 "Proof of Humanity" (POH) collection via standard `eth_call`s — the same
//! wire path a wallet / explorer uses. Covers:
//!
//!   * a **Verified** human has `balanceOf == 1`, `ownerOf(uint(addr)) == addr`, and a `tokenURI` that
//!     decodes to a JSON+SVG doc containing "Proof of Humanity" and the address;
//!   * an **Unverified** address has `balanceOf == 0` and `ownerOf` reverts;
//!   * a **transfer** attempt reverts (soulbound);
//!   * the metadata views (`name`/`symbol`/`supportsInterface`);
//!   * a Pending→**Verified** transition emits a mint `Transfer(0x0 → human, tokenId)` log and a
//!     **Revoke** emits a burn `Transfer(human → 0x0, tokenId)` log.
//!
//! Juror verdicts are signed with the well-known PUBLIC Anvil juror keys (#1..#3) the Chain seeds as
//! the deterministic devnet jury. NOT SECRETS — published in every EVM dev toolkit.

use std::net::SocketAddr;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    address, keccak256, Address as AlloyAddr, PrimitiveSignature, TxKind, U256,
};
use alloy_sol_types::SolCall;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use k256::ecdsa::SigningKey;

use ubi2_rpc::humanity::{challengeCall, submitVerdictCall, vouchCall, HUMANITY_HUB};
use ubi2_rpc::poh_nft::{
    balanceOfCall, nameCall, ownerOfCall, supportsInterfaceCall, symbolCall, tokenURICall,
    token_id_of, transferFromCall, IFACE_ERC165, IFACE_ERC721, IFACE_ERC721_METADATA,
};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, HumanStatus, EMISSION_PERIOD_SECS, UBI};

// ----- well-known PUBLIC devnet keys (Hardhat/Anvil accounts). NOT SECRETS. -----
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const JUROR1_KEY: [u8; 32] =
    hex32("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const JUROR2_KEY: [u8; 32] =
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
const JUROR1: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
const JUROR2: AlloyAddr = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
const JUROR3: AlloyAddr = address!("90F79bf6EB2c4f870365E785982E1f101E93b906");
const VOUCHER2: AlloyAddr = address!("15d34AAf54267DB7D7c367839AAf71A00a2C6A65");

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
        loop {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).await.expect("read");
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&buf).to_string();
        let body_start = text.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
        text[body_start..].to_string()
    };
    let resp = tokio::time::timeout(Duration::from_secs(5), fut)
        .await
        .unwrap_or_else(|_| panic!("rpc {method} timed out"));
    serde_json::from_str(&resp).unwrap_or_else(|e| panic!("bad json from {method}: {e}\n{resp}"))
}

async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex_encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send failed: {resp}"))
        .to_string()
}

/// `eth_call` to a hub with ABI calldata, returning the decoded `0x…` return bytes. Panics with the
/// JSON-RPC error body if the call reverted (so callers that *expect* a revert use `eth_call_raw`).
async fn eth_call(addr: SocketAddr, to: AlloyAddr, data: Vec<u8>) -> Vec<u8> {
    let resp = eth_call_raw(addr, to, data).await;
    let hex = resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("eth_call errored: {resp}"));
    hex_decode(hex.strip_prefix("0x").unwrap_or(hex))
}

/// `eth_call` returning the raw JSON-RPC response (so a test can assert on a revert error).
async fn eth_call_raw(addr: SocketAddr, to: AlloyAddr, data: Vec<u8>) -> serde_json::Value {
    let to_hex = format!("0x{}", hex_encode(to.as_slice()));
    let data_hex = format!("0x{}", hex_encode(&data));
    rpc(
        addr,
        "eth_call",
        serde_json::json!([{ "to": to_hex, "data": data_hex }, "latest"]),
    )
    .await
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}
fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Boot a Chain with the dev account + a second voucher (both Verified humans) and the three seeded
/// jurors, served over HTTP. Mirrors the M3 acceptance boot.
async fn boot(addr: SocketAddr, genesis: u64) -> (Chain, jsonrpsee::server::ServerHandle) {
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis);
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
            settled_balance: UBI,
            nonce: 0,
        });
        chain.register_juror(&j.into_array(), 0);
    }
    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(150)).await;
    (chain, handle)
}

fn verdict_call(case_id: u64, verdict: u8, confidence: u8) -> Vec<u8> {
    submitVerdictCall {
        caseId: U256::from(case_id),
        verdict,
        confidence,
    }
    .abi_encode()
}

/// The ERC-721 `Transfer(address,address,uint256)` topic0.
fn transfer_topic0() -> String {
    format!(
        "0x{}",
        hex_encode(keccak256(b"Transfer(address,address,uint256)").as_slice())
    )
}
/// A 32-byte left-padded address topic, as the receipt renders it.
fn addr_topic_hex(a: &AlloyAddr) -> String {
    let mut b = [0u8; 32];
    b[12..].copy_from_slice(a.as_slice());
    format!("0x{}", hex_encode(&b))
}

// =============================================================================================
// A Verified human: balanceOf==1, ownerOf(uint(addr))==addr, tokenURI decodes to JSON+SVG.
// Plus metadata (name/symbol/supportsInterface) and the soulbound revert.
// =============================================================================================
#[tokio::test]
async fn verified_human_is_a_poh_token() {
    let addr: SocketAddr = "127.0.0.1:18571".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (_chain, handle) = boot(addr, genesis).await;

    // DEV_ADDR is a seeded Verified human ⇒ it owns its PoH token.
    let token_id = token_id_of(&DEV_ADDR);

    // --- metadata: name "Proof of Humanity", symbol "POH". ---
    let out = eth_call(addr, HUMANITY_HUB, nameCall {}.abi_encode()).await;
    assert_eq!(
        nameCall::abi_decode_returns(&out, true).unwrap()._0,
        "Proof of Humanity"
    );
    let out = eth_call(addr, HUMANITY_HUB, symbolCall {}.abi_encode()).await;
    assert_eq!(
        symbolCall::abi_decode_returns(&out, true).unwrap()._0,
        "POH"
    );

    // --- supportsInterface: ERC165 + ERC721 + ERC721Metadata true, a random id false. ---
    for (id, want) in [
        (IFACE_ERC165, true),
        (IFACE_ERC721, true),
        (IFACE_ERC721_METADATA, true),
        ([0xde, 0xad, 0xbe, 0xef], false),
    ] {
        let out = eth_call(
            addr,
            HUMANITY_HUB,
            supportsInterfaceCall {
                interfaceId: id.into(),
            }
            .abi_encode(),
        )
        .await;
        assert_eq!(
            supportsInterfaceCall::abi_decode_returns(&out, true)
                .unwrap()
                ._0,
            want,
            "supportsInterface({id:?})"
        );
    }

    // --- balanceOf(DEV_ADDR) == 1. ---
    let out = eth_call(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: DEV_ADDR }.abi_encode(),
    )
    .await;
    assert_eq!(
        balanceOfCall::abi_decode_returns(&out, true).unwrap()._0,
        U256::from(1u8),
        "Verified human balanceOf == 1"
    );

    // --- ownerOf(uint(DEV_ADDR)) == DEV_ADDR. ---
    let out = eth_call(
        addr,
        HUMANITY_HUB,
        ownerOfCall { tokenId: token_id }.abi_encode(),
    )
    .await;
    assert_eq!(
        ownerOfCall::abi_decode_returns(&out, true).unwrap()._0,
        DEV_ADDR,
        "ownerOf(uint(addr)) == addr"
    );

    // --- tokenURI(tokenId) → data:application/json;base64 → JSON{name, image:svg} with the brand. ---
    let out = eth_call(
        addr,
        HUMANITY_HUB,
        tokenURICall { tokenId: token_id }.abi_encode(),
    )
    .await;
    let uri = tokenURICall::abi_decode_returns(&out, true).unwrap()._0;
    let b64 = uri
        .strip_prefix("data:application/json;base64,")
        .expect("tokenURI is a base64 JSON data-URI");
    let json_bytes = B64.decode(b64).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&String::from_utf8(json_bytes).unwrap())
        .expect("tokenURI JSON parses");
    assert!(
        meta["name"].as_str().unwrap().contains("Proof of Humanity"),
        "name carries the collection brand"
    );
    let dev_full = format!("0x{}", hex_encode(DEV_ADDR.as_slice()));
    assert!(
        meta["description"].as_str().unwrap().contains(&dev_full),
        "description carries the full address"
    );
    // The image is an inline base64 SVG carrying "Proof of Humanity" + the gradient fingerprint.
    let image = meta["image"].as_str().unwrap();
    let svg_b64 = image
        .strip_prefix("data:image/svg+xml;base64,")
        .expect("image is an inline svg data-uri");
    let svg = String::from_utf8(B64.decode(svg_b64).unwrap()).unwrap();
    assert!(svg.starts_with("<svg") && svg.contains("</svg>"));
    assert!(svg.contains("Proof of Humanity"));
    assert!(
        svg.contains("#FFE24B") && svg.contains("#FF6B8A"),
        "card uses the locked gold→pink PoH gradient"
    );
    assert!(svg.contains("url(#g)"), "head emblem is gradient-filled");
    println!(
        "[poh-nft] Verified DEV is token #{token_id}; tokenURI = {}",
        meta["name"]
    );

    // --- soulbound: transferFrom on the HumanityHub reverts. ---
    let resp = eth_call_raw(
        addr,
        HUMANITY_HUB,
        transferFromCall {
            from: DEV_ADDR,
            to: JUROR1,
            tokenId: token_id,
        }
        .abi_encode(),
    )
    .await;
    assert!(
        resp.get("error").is_some(),
        "transferFrom must revert (soulbound), got {resp}"
    );
    let msg = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("soulbound") || msg.contains("revert"),
        "revert reason mentions soulbound, got {msg:?}"
    );
    println!("[poh-nft] transferFrom reverted (soulbound): {msg}");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// An Unverified address has no token: balanceOf == 0, ownerOf reverts.
// =============================================================================================
#[tokio::test]
async fn unverified_address_has_no_token() {
    let addr: SocketAddr = "127.0.0.1:18572".parse().unwrap();
    let genesis = now_secs();
    let (_chain, handle) = boot(addr, genesis).await;

    // A fresh, never-registered address (Anvil acct #5).
    let stranger = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");

    // balanceOf == 0.
    let out = eth_call(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: stranger }.abi_encode(),
    )
    .await;
    assert_eq!(
        balanceOfCall::abi_decode_returns(&out, true).unwrap()._0,
        U256::ZERO,
        "Unverified balanceOf == 0"
    );

    // ownerOf(uint(stranger)) reverts (nonexistent token).
    let resp = eth_call_raw(
        addr,
        HUMANITY_HUB,
        ownerOfCall {
            tokenId: token_id_of(&stranger),
        }
        .abi_encode(),
    )
    .await;
    assert!(
        resp.get("error").is_some(),
        "ownerOf for an unverified address must revert, got {resp}"
    );
    println!("[poh-nft] unverified address: balanceOf 0, ownerOf reverts");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// Mint on Verified, burn on Revoke: the lifecycle emits the standard ERC-721 Transfer logs.
// =============================================================================================
#[tokio::test]
async fn verified_mints_and_revoke_burns() {
    let addr: SocketAddr = "127.0.0.1:18573".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    // The subject under challenge is the already-Verified VOUCHER2. A Sybil quorum revokes it ⇒ burn.
    let subject = VOUCHER2;
    let subj_topic = addr_topic_hex(&subject);
    let token_id_hex = format!(
        "0x{}",
        hex_encode(&token_id_of(&subject).to_be_bytes::<32>())
    );
    let zero_topic = addr_topic_hex(&AlloyAddr::ZERO);

    // --- challenge VOUCHER2: Verified → Challenged (its token leaves existence ⇒ a burn). ---
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        challengeCall {
            subject,
            evidenceRef: [0x99u8; 32].into(),
        }
        .abi_encode(),
        0,
    );
    let ch_hash = send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([ch_hash]),
    )
    .await;
    let logs = receipt["result"]["logs"].as_array().expect("logs");
    // A burn Transfer(subject → 0x0, tokenId) accompanies the Verified→Challenged StatusChanged.
    let burn = logs.iter().find(|l| {
        l["topics"][0] == serde_json::json!(transfer_topic0())
            && l["topics"][1] == serde_json::json!(subj_topic)
            && l["topics"][2] == serde_json::json!(zero_topic)
    });
    assert!(
        burn.is_some(),
        "Verified→Challenged burns the PoH token, got {logs:?}"
    );
    assert_eq!(
        burn.unwrap()["topics"][3],
        serde_json::json!(token_id_hex),
        "burn tokenId == address as uint160"
    );

    // While Challenged, the token does not exist: balanceOf 0, ownerOf reverts.
    let out = eth_call(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: subject }.abi_encode(),
    )
    .await;
    assert_eq!(
        balanceOfCall::abi_decode_returns(&out, true).unwrap()._0,
        U256::ZERO,
        "Challenged subject has no live token"
    );

    // --- two jurors submit Sybil (QUORUM=2) ⇒ subject Revoked (terminal — already burned). ---
    let case_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();
    let raw = sign_tx(&JUROR1_KEY, HUMANITY_HUB, 0, verdict_call(case_id, 1, 2), 0);
    send_ok(addr, raw).await;
    let raw = sign_tx(&JUROR2_KEY, HUMANITY_HUB, 0, verdict_call(case_id, 1, 2), 0);
    let v2_hash = send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    let revoked = rpc(
        addr,
        "ubi_getHuman",
        serde_json::json!([format!("0x{}", hex_encode(subject.as_slice()))]),
    )
    .await;
    assert_eq!(
        revoked["result"]["status"], "Revoked",
        "subject Revoked by Sybil quorum"
    );
    // The Revoke receipt carries StatusChanged(Revoked); no *second* burn fires (token was already
    // burned at Challenged) — Challenged→Revoked is not a Verified→not-Verified crossing.
    let receipt2 = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([v2_hash]),
    )
    .await;
    let logs2 = receipt2["result"]["logs"].as_array().expect("logs2");
    let extra_burn = logs2
        .iter()
        .any(|l| l["topics"][0] == serde_json::json!(transfer_topic0()));
    assert!(
        !extra_burn,
        "no duplicate burn on Challenged→Revoked (token already burned), got {logs2:?}"
    );
    println!("[poh-nft] burn fired at Verified→Challenged; Revoke is terminal (no double burn)");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// Mint on Verified: a fresh address driven Unverified → Pending → Verified emits the standard
// ERC-721 mint Transfer(0x0 → human, tokenId), and ownerOf then resolves the new token.
// =============================================================================================
#[tokio::test]
async fn verified_transition_mints() {
    let addr: SocketAddr = "127.0.0.1:18574".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    // A fresh, never-registered subject (Anvil acct #5). The two seeded Verified humans (DEV +
    // VOUCHER2) vouch for it to reach MIN_VOUCHES=2.
    let subject_key: [u8; 32] =
        hex32("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");
    let subject = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
    let subj_topic = addr_topic_hex(&subject);
    let zero_topic = addr_topic_hex(&AlloyAddr::ZERO);
    let token_hex = format!(
        "0x{}",
        hex_encode(&token_id_of(&subject).to_be_bytes::<32>())
    );

    // requestVerification → Pending.
    let raw = sign_tx(
        &subject_key,
        HUMANITY_HUB,
        0,
        ubi2_rpc::humanity::requestVerificationCall {
            livenessRef: [0x11u8; 32].into(),
        }
        .abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());
    assert_eq!(
        chain.get_human(&subject.into_array()).unwrap().status,
        HumanStatus::Pending
    );

    // Two distinct Verified vouches (DEV + VOUCHER2), both seeded as Verified humans by `boot`.
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        vouchCall { vouchee: subject }.abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    let raw = sign_tx(
        &hex32("47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"), // VOUCHER2 key
        HUMANITY_HUB,
        0,
        vouchCall { vouchee: subject }.abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // Clear the challenge window; the auto-finalize sweep flips the subject Verified and mints. The
    // mint is carried by the synthetic finalize-sweep tx — scan each block's receipts for it.
    let mut mint_log: Option<serde_json::Value> = None;
    for _ in 0..8 {
        let b = chain.produce_block(now_secs());
        for tx in &b.txs {
            let h = format!("0x{}", hex_encode(tx.hash.as_slice()));
            let r = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([h])).await;
            if let Some(logs) = r["result"]["logs"].as_array() {
                if let Some(l) = logs.iter().find(|l| {
                    l["topics"][0] == serde_json::json!(transfer_topic0())
                        && l["topics"][1] == serde_json::json!(zero_topic)
                        && l["topics"][2] == serde_json::json!(subj_topic)
                }) {
                    mint_log = Some(l.clone());
                }
            }
        }
        if mint_log.is_some() {
            break;
        }
    }
    let mint = mint_log.expect("Pending→Verified must emit a mint Transfer(0x0 → subject)");
    assert_eq!(
        mint["topics"][3],
        serde_json::json!(token_hex),
        "mint tokenId == address as uint160"
    );
    assert_eq!(
        chain.get_human(&subject.into_array()).unwrap().status,
        HumanStatus::Verified,
        "subject finalized to Verified"
    );

    // The freshly-minted token is now live over eth_call: ownerOf resolves, balanceOf == 1.
    let out = eth_call(
        addr,
        HUMANITY_HUB,
        ownerOfCall {
            tokenId: token_id_of(&subject),
        }
        .abi_encode(),
    )
    .await;
    assert_eq!(
        ownerOfCall::abi_decode_returns(&out, true).unwrap()._0,
        subject,
        "newly Verified subject owns its token"
    );
    let out = eth_call(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: subject }.abi_encode(),
    )
    .await;
    assert_eq!(
        balanceOfCall::abi_decode_returns(&out, true).unwrap()._0,
        U256::from(1u8)
    );
    println!("[poh-nft] mint fired at Pending→Verified; ownerOf/balanceOf resolve the fresh token");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
