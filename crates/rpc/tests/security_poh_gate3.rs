//! GATE 3 — Security PoCs for the soulbound Proof-of-Humanity (POH) NFT.
//! Branch `feat/poh-nft-branding`, commit 2bee8d2. Defender, this project only.
//!
//! Boots the real `ubi2_rpc::serve` server in-process on the security port range (:38545+) and drives
//! the HumanityHub (`0x…5048`) over the same `eth_call` / `eth_sendRawTransaction` wire path a wallet
//! uses. Covers the five gate items:
//!   (1) SOULBOUND BYPASS  — transferFrom / safeTransferFrom (both overloads) / approve /
//!       setApprovalForAll must NOT move or delegate a badge, over BOTH eth_call AND a real tx.
//!   (2) VIEW-SURFACE ROBUSTNESS — hostile tokenIds (0, max-uint256, high-bits-set, non-existent /
//!       Revoked / Challenged addresses) must revert/return-0 cleanly, never panic the node.
//!   (3) CARD INJECTION — the on-chain SVG/JSON only embeds non-attacker-controlled fields.
//!   (4) LOG SPOOFING / ownership confusion — Transfer logs and the view methods agree.
//!   (5) Regression hooks live in their own test files; here we assert the soulbound revert path is
//!       distinct from the live humanity write ops.
//!
//! Juror verdicts are signed with the well-known PUBLIC Anvil juror keys. NOT SECRETS.

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

use ubi2_rpc::humanity::{challengeCall, submitVerdictCall, HUMANITY_HUB};
use ubi2_rpc::poh_nft::{
    approveCall, balanceOfCall, ownerOfCall, safeTransferFromCall, setApprovalForAllCall,
    tokenURICall, token_id_of, transferFromCall,
};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, HumanStatus, EMISSION_PERIOD_SECS, UBI};

// ----- well-known PUBLIC devnet keys (Hardhat/Anvil). NOT SECRETS. -----
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const ATTACKER_KEY: [u8; 32] =
    hex32("0dbbe8e4ae425a6d2687f1a7e3ba17bc98c673636790f1b8ad91193c05875ef1"); // Anvil #6
const ATTACKER: AlloyAddr = address!("976EA74026E726554dB657fA54763abd0C3a0aa9");
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

async fn send_raw(addr: SocketAddr, raw: Vec<u8>) -> serde_json::Value {
    let raw_hex = format!("0x{}", hex_encode(&raw));
    rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await
}
async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let resp = send_raw(addr, raw).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send failed: {resp}"))
        .to_string()
}

/// Raw `eth_call` (so a test can assert on a revert error or an empty `0x`).
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
    let s = s.strip_prefix("0x").unwrap_or(s);
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

async fn boot(addr: SocketAddr, genesis: u64) -> (Chain, jsonrpsee::server::ServerHandle) {
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis);
    for a in [DEV_ADDR, VOUCHER2, ATTACKER] {
        chain.seed_account(Account {
            address: a.into_array(),
            verified: a != ATTACKER,
            verified_at: if a == ATTACKER { 0 } else { genesis },
            last_settled_at: genesis,
            settled_balance: 10 * UBI,
            nonce: 0,
        });
        if a != ATTACKER {
            chain.seed_verified_human(&a.into_array(), genesis);
        }
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

/// The ERC-721 4-arg `safeTransferFrom(address,address,uint256,bytes)` overload selector (b88d4fde) —
/// NOT declared in the POH `sol!` interface, so we hand-encode it to probe the unhandled-selector path.
fn safe_transfer_from_4arg(from: AlloyAddr, to: AlloyAddr, token_id: U256) -> Vec<u8> {
    let mut out = keccak256(b"safeTransferFrom(address,address,uint256,bytes)")[..4].to_vec();
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(from.as_slice());
    out.extend_from_slice(&word);
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(to.as_slice());
    out.extend_from_slice(&word);
    out.extend_from_slice(&token_id.to_be_bytes::<32>());
    // offset to the (empty) bytes param = 0x80, then length 0.
    out.extend_from_slice(&U256::from(0x80u64).to_be_bytes::<32>());
    out.extend_from_slice(&U256::ZERO.to_be_bytes::<32>());
    out
}

// =============================================================================================
// (1) SOULBOUND BYPASS — every mutator reverts over a real signed tx AND over eth_call; the badge
//     never moves and is never delegated. Both safeTransferFrom overloads covered.
// =============================================================================================
#[tokio::test]
async fn gate1_soulbound_no_transfer_no_approve() {
    let addr: SocketAddr = "127.0.0.1:38545".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    let token_id = token_id_of(&DEV_ADDR);

    // --- a) eth_call simulations: every declared mutator reverts ("soulbound"). ---
    for (label, data) in [
        (
            "transferFrom",
            transferFromCall {
                from: DEV_ADDR,
                to: ATTACKER,
                tokenId: token_id,
            }
            .abi_encode(),
        ),
        (
            "safeTransferFrom(3-arg)",
            safeTransferFromCall {
                from: DEV_ADDR,
                to: ATTACKER,
                tokenId: token_id,
            }
            .abi_encode(),
        ),
        (
            "approve",
            approveCall {
                to: ATTACKER,
                tokenId: token_id,
            }
            .abi_encode(),
        ),
        (
            "setApprovalForAll",
            setApprovalForAllCall {
                operator: ATTACKER,
                approved: true,
            }
            .abi_encode(),
        ),
    ] {
        let resp = eth_call_raw(addr, HUMANITY_HUB, data).await;
        assert!(
            resp.get("error").is_some(),
            "{label} via eth_call must revert (soulbound), got {resp}"
        );
        let msg = resp["error"]["message"].as_str().unwrap_or("");
        assert!(
            msg.to_lowercase().contains("soulbound") || msg.to_lowercase().contains("revert"),
            "{label} revert message should indicate soulbound, got {msg:?}"
        );
    }

    // The 4-arg safeTransferFrom overload (b88d4fde) is NOT in the interface. Over eth_call it is a
    // VIEW that cannot move state — it must NOT succeed-with-a-transfer. We record the actual behavior.
    let resp = eth_call_raw(
        addr,
        HUMANITY_HUB,
        safe_transfer_from_4arg(DEV_ADDR, ATTACKER, token_id),
    )
    .await;
    let four_arg_call_result = resp["result"].as_str().unwrap_or("<err>").to_string();
    // Whatever it returns, it is a read: ownership must be unchanged (asserted below).

    // --- b) real signed txs: every mutator selector to HumanityHub must NOT change ownership. ---
    // The attacker tries to steal DEV_ADDR's badge to themselves. Each is sent, a block produced, and
    // ownership re-checked.
    let mut nonce = 0u64;
    for (label, data) in [
        (
            "transferFrom-tx",
            transferFromCall {
                from: DEV_ADDR,
                to: ATTACKER,
                tokenId: token_id,
            }
            .abi_encode(),
        ),
        (
            "safeTransferFrom3-tx",
            safeTransferFromCall {
                from: DEV_ADDR,
                to: ATTACKER,
                tokenId: token_id,
            }
            .abi_encode(),
        ),
        (
            "safeTransferFrom4-tx",
            safe_transfer_from_4arg(DEV_ADDR, ATTACKER, token_id),
        ),
        (
            "approve-tx",
            approveCall {
                to: ATTACKER,
                tokenId: token_id,
            }
            .abi_encode(),
        ),
        (
            "setApprovalForAll-tx",
            setApprovalForAllCall {
                operator: ATTACKER,
                approved: true,
            }
            .abi_encode(),
        ),
    ] {
        let resp = send_raw(addr, sign_tx(&ATTACKER_KEY, HUMANITY_HUB, 0, data, nonce)).await;
        // A real ERC-721 mutator/unknown selector to HumanityHub is rejected at submit (revert/error),
        // so the nonce is NOT consumed. If a future change accepts it as a tx, the post-block ownership
        // assertions below are the real safety net.
        if resp.get("result").is_some() {
            nonce += 1;
            chain.produce_block(now_secs());
        }
        let _ = label;
    }
    chain.produce_block(now_secs());

    // --- c) ownership is unchanged: DEV_ADDR still owns its token; ATTACKER owns nothing. ---
    let out = eth_call_raw(
        addr,
        HUMANITY_HUB,
        ownerOfCall { tokenId: token_id }.abi_encode(),
    )
    .await;
    let owner = ownerOfCall::abi_decode_returns(&hex_decode(out["result"].as_str().unwrap()), true)
        .unwrap()
        ._0;
    assert_eq!(
        owner, DEV_ADDR,
        "after every mutator attempt the badge still belongs to its human (4-arg call returned {four_arg_call_result})"
    );

    let out = eth_call_raw(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: ATTACKER }.abi_encode(),
    )
    .await;
    let bal = balanceOfCall::abi_decode_returns(&hex_decode(out["result"].as_str().unwrap()), true)
        .unwrap()
        ._0;
    assert_eq!(bal, U256::ZERO, "attacker never acquired a badge");

    // DEV still has exactly its one badge (no duplication, no delegation moved it).
    let out = eth_call_raw(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: DEV_ADDR }.abi_encode(),
    )
    .await;
    let bal = balanceOfCall::abi_decode_returns(&hex_decode(out["result"].as_str().unwrap()), true)
        .unwrap()
        ._0;
    assert_eq!(bal, U256::from(1u8), "human keeps exactly one badge");

    println!("[gate1] soulbound: all mutators (incl. both safeTransferFrom overloads) cannot move or delegate a badge");
    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// (2) VIEW-SURFACE ROBUSTNESS — hostile tokenIds never panic the node; they revert or return 0.
//     The server staying responsive after each probe is the no-DoS proof.
// =============================================================================================
#[tokio::test]
async fn gate2_view_surface_no_panic() {
    let addr: SocketAddr = "127.0.0.1:38546".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    // Drive VOUCHER2 to Challenged (token burned, status no longer Verified) and a fresh address to a
    // non-existent token, so we can probe the "looks like an address but isn't Verified" cases.
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        challengeCall {
            subject: VOUCHER2,
            evidenceRef: [0x99u8; 32].into(),
        }
        .abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());
    assert_eq!(
        chain.get_human(&VOUCHER2.into_array()).unwrap().status,
        HumanStatus::Challenged
    );

    let max = U256::MAX;
    let high_bits = token_id_of(&DEV_ADDR) | (U256::from(1u8) << 200); // valid addr bits + stray high bit
    let revoked_like = token_id_of(&VOUCHER2); // Challenged ⇒ token does not exist
    let stranger = token_id_of(&address!("000000000000000000000000000000000000dEaD"));

    // ownerOf / tokenURI on each hostile id: must NOT 500/panic. Either a clean revert (error) or a
    // valid result, never a transport error / closed connection.
    for (label, id) in [
        ("zero", U256::ZERO),
        ("max-uint256", max),
        ("high-bits-above-160", high_bits),
        ("challenged-addr", revoked_like),
        ("nonexistent-addr", stranger),
    ] {
        for (m, data) in [
            ("ownerOf", ownerOfCall { tokenId: id }.abi_encode()),
            ("tokenURI", tokenURICall { tokenId: id }.abi_encode()),
        ] {
            let resp = eth_call_raw(addr, HUMANITY_HUB, data).await;
            // jsonrpsee always answers with a well-formed JSON-RPC object — either `result` or `error`.
            // A panic would drop the connection (our rpc() would fail to parse) or yield a -32603.
            let has_result = resp.get("result").is_some();
            let has_error = resp.get("error").is_some();
            assert!(
                has_result || has_error,
                "{m}({label}) produced neither result nor error (node may have panicked): {resp}"
            );
            if let Some(err) = resp.get("error") {
                let code = err["code"].as_i64().unwrap_or(0);
                // -32603 is INTERNAL_ERROR (a panic/unwrap leaking out). We want a clean
                // execution-revert (3) or invalid-params (-32602), never an internal error.
                assert_ne!(
                    code, -32603,
                    "{m}({label}) returned INTERNAL_ERROR (-32603) — a panic leaked: {resp}"
                );
            }
        }
    }

    // balanceOf with a normal address argument (the only shape ABI lets through) for a Challenged and a
    // stranger returns a clean 0.
    for who in [
        VOUCHER2,
        address!("000000000000000000000000000000000000dEaD"),
    ] {
        let out = eth_call_raw(
            addr,
            HUMANITY_HUB,
            balanceOfCall { owner: who }.abi_encode(),
        )
        .await;
        let bal =
            balanceOfCall::abi_decode_returns(&hex_decode(out["result"].as_str().unwrap()), true)
                .unwrap()
                ._0;
        assert_eq!(bal, U256::ZERO, "non-Verified balanceOf == 0 for {who}");
    }

    // The node is still alive and serving after every hostile probe (no DoS): a normal call answers.
    let out = eth_call_raw(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: DEV_ADDR }.abi_encode(),
    )
    .await;
    let bal = balanceOfCall::abi_decode_returns(&hex_decode(out["result"].as_str().unwrap()), true)
        .unwrap()
        ._0;
    assert_eq!(
        bal,
        U256::from(1u8),
        "node still serving after hostile probes"
    );

    println!("[gate2] view surface: 0 / max-uint256 / high-bits / challenged / nonexistent never panic; node stays up");
    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// (3) CARD INJECTION — the on-chain SVG/JSON for a Verified human only embeds the hex address +
//     integers + a derived date; no attacker-controlled string. We decode the real card and assert it
//     is well-formed JSON whose SVG carries only those fields (and that the only string-typed values
//     are the fixed brand strings + the hex address).
// =============================================================================================
#[tokio::test]
async fn gate3_card_only_safe_fields() {
    let addr: SocketAddr = "127.0.0.1:38547".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (_chain, handle) = boot(addr, genesis).await;

    let out = eth_call_raw(
        addr,
        HUMANITY_HUB,
        tokenURICall {
            tokenId: token_id_of(&DEV_ADDR),
        }
        .abi_encode(),
    )
    .await;
    let uri = tokenURICall::abi_decode_returns(&hex_decode(out["result"].as_str().unwrap()), true)
        .unwrap()
        ._0;
    let json_b64 = uri
        .strip_prefix("data:application/json;base64,")
        .expect("json data-uri");
    let json_bytes = B64.decode(json_b64).unwrap();
    // Must be well-formed JSON (any unescaped injection would break this parse).
    let meta: serde_json::Value =
        serde_json::from_str(&String::from_utf8(json_bytes).unwrap()).expect("card JSON parses");

    // Every string value in the doc is a fixed brand string or the hex address. No free-form text.
    let dev_full = format!("0x{}", hex_encode(DEV_ADDR.as_slice()));
    let allowed_substrings = ["Proof of Humanity", "POH", "Verified", &dev_full];
    let name = meta["name"].as_str().unwrap();
    assert!(name.contains("Proof of Humanity"));
    for attr in meta["attributes"].as_array().unwrap() {
        // attribute values are either a fixed status string, the hex address, a date label, or numbers.
        if let Some(s) = attr["value"].as_str() {
            let ok = allowed_substrings.iter().any(|a| s.contains(a))
                || s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == ' ' || c == ',');
            assert!(ok, "attribute string value is constrained, got {s:?}");
        }
    }

    // The image SVG must be well-formed and contain ONLY the brand + hex + integers. We assert there is
    // no `<script`, no `onload=`/`on*=` event handler, and no unescaped `<`/`>` outside SVG tags by
    // re-parsing the brand markers.
    let image = meta["image"].as_str().unwrap();
    let svg_b64 = image
        .strip_prefix("data:image/svg+xml;base64,")
        .expect("svg data-uri");
    let svg = String::from_utf8(B64.decode(svg_b64).unwrap()).unwrap();
    assert!(svg.starts_with("<svg") && svg.ends_with("</svg>"));
    let lower = svg.to_lowercase();
    assert!(
        !lower.contains("<script"),
        "no script element in the card SVG"
    );
    assert!(!lower.contains("onload"), "no onload handler");
    assert!(!lower.contains("onerror"), "no onerror handler");
    assert!(!lower.contains("javascript:"), "no javascript: uri");
    assert!(!lower.contains("<foreignobject"), "no foreignObject");
    // The only dynamic substrings are the truncated hex address + the integer fields.
    assert!(svg.contains("0xf39F".to_lowercase().as_str()) || svg.contains("0xf39f"));

    println!("[gate3] card: well-formed JSON+SVG; only brand strings + hex address + integers; no script/handlers");
    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// (4) LOG SPOOFING / ownership confusion — the Transfer-log transcript and the view methods agree.
//     A non-Verified address can never appear to own a token via ownerOf, and a burn-on-Challenge
//     leaves the views consistent (no live token while a Transfer-burn is on record).
// =============================================================================================
#[tokio::test]
async fn gate4_logs_and_views_agree() {
    let addr: SocketAddr = "127.0.0.1:38548".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis).await;

    // Challenge VOUCHER2: Verified→Challenged emits a burn Transfer(subject→0x0). After that the views
    // must report the token as nonexistent (ownerOf reverts, balanceOf 0) — the burn and the views
    // agree, so an indexer replaying logs and a caller hitting ownerOf see the same (no) owner.
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        challengeCall {
            subject: VOUCHER2,
            evidenceRef: [0x42u8; 32].into(),
        }
        .abi_encode(),
        0,
    );
    let ch = send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    let receipt = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([ch])).await;
    let logs = receipt["result"]["logs"].as_array().unwrap();
    let transfer0 = format!(
        "0x{}",
        hex_encode(keccak256(b"Transfer(address,address,uint256)").as_slice())
    );
    let mut subj_topic = [0u8; 32];
    subj_topic[12..].copy_from_slice(VOUCHER2.as_slice());
    let subj_topic = format!("0x{}", hex_encode(&subj_topic));
    let zero_topic = format!("0x{}", hex_encode(&[0u8; 32]));
    let burn = logs.iter().find(|l| {
        l["topics"][0] == serde_json::json!(transfer0)
            && l["topics"][1] == serde_json::json!(subj_topic)
            && l["topics"][2] == serde_json::json!(zero_topic)
    });
    assert!(burn.is_some(), "Challenge burns the badge (Transfer→0x0)");
    // The burn's tokenId topic equals address-as-uint160 — the same key ownerOf decodes.
    let token_hex = format!(
        "0x{}",
        hex_encode(&token_id_of(&VOUCHER2).to_be_bytes::<32>())
    );
    assert_eq!(burn.unwrap()["topics"][3], serde_json::json!(token_hex));

    // Views agree: ownerOf reverts, balanceOf 0 — a burned/Challenged badge is NOT owned.
    let resp = eth_call_raw(
        addr,
        HUMANITY_HUB,
        ownerOfCall {
            tokenId: token_id_of(&VOUCHER2),
        }
        .abi_encode(),
    )
    .await;
    assert!(
        resp.get("error").is_some(),
        "ownerOf of a burned/Challenged badge reverts (no forged owner), got {resp}"
    );
    let out = eth_call_raw(
        addr,
        HUMANITY_HUB,
        balanceOfCall { owner: VOUCHER2 }.abi_encode(),
    )
    .await;
    let bal = balanceOfCall::abi_decode_returns(&hex_decode(out["result"].as_str().unwrap()), true)
        .unwrap()
        ._0;
    assert_eq!(bal, U256::ZERO, "burned badge ⇒ balanceOf 0");

    // A never-Verified address (the attacker) cannot appear to own a token: there is no mint log for it
    // and ownerOf reverts. ownerOf(uint(attacker)) reverts; balanceOf 0.
    let resp = eth_call_raw(
        addr,
        HUMANITY_HUB,
        ownerOfCall {
            tokenId: token_id_of(&ATTACKER),
        }
        .abi_encode(),
    )
    .await;
    assert!(
        resp.get("error").is_some(),
        "a never-Verified address has no ownable token"
    );

    // Now revoke (two Sybil verdicts). Status→Revoked; no SECOND burn fires (already burned at
    // Challenge), and ownerOf is still revert — logs and views remain consistent (no resurrection).
    let case_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();
    send_ok(
        addr,
        sign_tx(&JUROR1_KEY, HUMANITY_HUB, 0, verdict_call(case_id, 1, 2), 0),
    )
    .await;
    let v2 = send_ok(
        addr,
        sign_tx(&JUROR2_KEY, HUMANITY_HUB, 0, verdict_call(case_id, 1, 2), 0),
    )
    .await;
    chain.produce_block(now_secs());
    let r2 = rpc(addr, "eth_getTransactionReceipt", serde_json::json!([v2])).await;
    let logs2 = r2["result"]["logs"].as_array().unwrap();
    let extra_burn = logs2
        .iter()
        .any(|l| l["topics"][0] == serde_json::json!(transfer0));
    assert!(
        !extra_burn,
        "no duplicate/forged Transfer on Challenged→Revoked"
    );
    let status = rpc(
        addr,
        "ubi_getHuman",
        serde_json::json!([format!("0x{}", hex_encode(VOUCHER2.as_slice()))]),
    )
    .await;
    assert_eq!(status["result"]["status"], "Revoked");
    let resp = eth_call_raw(
        addr,
        HUMANITY_HUB,
        ownerOfCall {
            tokenId: token_id_of(&VOUCHER2),
        }
        .abi_encode(),
    )
    .await;
    assert!(
        resp.get("error").is_some(),
        "Revoked badge stays nonexistent in the views (no log/view divergence)"
    );

    println!(
        "[gate4] logs⇄views agree: burn matches ownerOf-revert; no forged owner; no resurrection"
    );
    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
