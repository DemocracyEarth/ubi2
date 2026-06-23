//! EXPL-2 deep decoded explorer reads integration test (board task: rich block-explorer RPC).
//!
//! Boots the real [`ubi2_rpc::serve`] HTTP JSON-RPC server in-process (NON-DEFAULT port) and drives it
//! like a standard EVM client — the same wire path a wallet/explorer uses. Produces a handful of txs of
//! every flavor (a plain **transfer**, a **vouch** to the HumanityHub, a **deploy** + **fund** +
//! **invoke** to the ContractHub) and asserts that the two new explorer surfaces decode them richly:
//!
//! * `ubi_getBlock(numberOrHashOrTag)` → full header
//!   (number/hash/parentHash/timestamp/txCount/roots) + the FULL list of its txs, each decoded
//!   (from/to/value/nonce/fee/kind, the decoded system-hub `call`, the decoded `logs`, the `result`).
//! * `ubi_getTransaction(hash)` → the decoded tx: the system-hub `call` (hub + method + args), the
//!   decoded `logs`, and the RESULTING state effect/verdict/status (an invoke → the committed
//!   `CanonicalEffect`; a vouch → no resolvable case; a transfer → a plain value move).
//!
//! Every assertion is on a deterministic shape (hex quantities, 0x addresses/hashes) the node computes
//! purely from `(stored tx, settled state)` — no model calls (the deterministic MockOracle /
//! MockInterpreter run at block time), so this maps 1:1 to the spec's reproducibility invariant (I2).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::contracts::{
    deployContractCall, derive_trigger, fundContractCall, invokeContractCall, CONTRACT_HUB,
};
use ubi2_rpc::humanity::{requestVerificationCall, vouchCall, HUMANITY_HUB};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, CanonicalEffect, MockInterpreter, Op, UBI};

/// Well-known PUBLIC devnet keys (Hardhat/Anvil accounts). NOT SECRETS.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// A payee account (Anvil acct #5) — receives a plain transfer + the contract's Transfer-from-escrow.
const PAYEE: AlloyAddr = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
/// A vouchee account (Anvil acct #6) — opens a registration, then the dev human vouches for it.
const VOUCHEE: AlloyAddr = address!("976EA74026E726554dB657fA54763abd0C3a0aa9");
const VOUCHEE_KEY: [u8; 32] =
    hex32("92db14e403b83dfe3df233f83dfa3a0d7096f21ca9b0d6d6b8d88b2b4ec1564e");

/// Anvil accounts #1-#3 — seeded devnet jurors / interpreters (the quorum, JURY_SIZE=3).
const JUROR1: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
const JUROR2: AlloyAddr = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
const JUROR3: AlloyAddr = address!("90F79bf6EB2c4f870365E785982E1f101E93b906");

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
        .unwrap_or_else(|| panic!("send failed: {resp}"))
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

/// Boot a Chain with the dev account (a funded Verified human) + a second Verified human (the vouchee)
/// + three seeded jurors/interpreters, running the given deterministic `interpreter`, served over HTTP.
async fn boot(
    addr: SocketAddr,
    genesis: u64,
    interpreter: Arc<dyn ubi2_runtime::ContractInterpreter>,
) -> (Chain, jsonrpsee::server::ServerHandle) {
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis).with_interpreter(interpreter);
    // The dev account is a funded Verified human (so it accrues UBI to transfer / fund an escrow).
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: genesis,
        last_settled_at: genesis,
        settled_balance: 0,
        nonce: 0,
    });
    chain.seed_verified_human(&DEV_ADDR.into_array(), genesis);
    // The vouchee opens its own registration in-test (so it is Pending and a vouch is accepted).
    for j in [JUROR1, JUROR2, JUROR3] {
        chain.register_juror(&j.into_array(), 0);
    }
    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(150)).await;
    (chain, handle)
}

/// Drive transfer / vouch / deploy / fund / invoke txs and assert ubi_getBlock + ubi_getTransaction
/// return the decoded shapes for every kind.
#[tokio::test]
async fn decoded_block_and_transaction_shapes() {
    let addr: SocketAddr = "127.0.0.1:18581".parse().unwrap();
    // Dev genesis far in the past so it already holds emission to transfer + fund.
    let genesis = now_secs() - 100 * 3_600;

    // The contract intent: "on the trigger, pay 4 UBI from escrow to the payee". The node derives the
    // trigger bytes from the on-chain triggerRef; script the interpreter on those exact bytes so every
    // juror emits the same Transfer effect and the quorum commits it (I1/I5).
    let trigger_ref = [0x91u8; 32];
    let trigger_bytes = derive_trigger(&trigger_ref);
    let pay4 = CanonicalEffect::new(vec![Op::Transfer {
        to: PAYEE.into_array(),
        amount: 4 * UBI,
    }]);
    let interp = Arc::new(MockInterpreter::default().with_trigger(&trigger_bytes, pay4.clone()));
    let (chain, handle) = boot(addr, genesis, interp).await;

    let payee_hex = format!("0x{}", hex::encode(PAYEE.as_slice()));
    let vouchee_hex = format!("0x{}", hex::encode(VOUCHEE.as_slice()));

    // ============================ block 1: a plain transfer ============================
    let transfer_hash = send_ok(addr, sign_tx(&DEV_PRIVKEY, PAYEE, 7 * UBI, Vec::new(), 0)).await;
    let b1 = chain.produce_block(now_secs());

    // ubi_getBlock by number → full header + the decoded transfer tx.
    let block = rpc(
        addr,
        "ubi_getBlock",
        serde_json::json!([format!("0x{:x}", b1.number)]),
    )
    .await;
    let blk = &block["result"];
    assert_eq!(
        u64::from_str_radix(blk["number"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
        b1.number,
        "block number"
    );
    assert!(blk["hash"].as_str().unwrap().starts_with("0x"));
    assert!(blk["parentHash"].as_str().unwrap().starts_with("0x"));
    assert!(blk["timestamp"].as_str().unwrap().starts_with("0x"));
    assert_eq!(blk["txCount"].as_u64().unwrap(), 1, "one tx in the block");
    assert!(blk["stateRoot"].as_str().unwrap().starts_with("0x"));
    let txs = blk["transactions"].as_array().expect("full tx list");
    assert_eq!(txs.len(), 1);
    let t0 = &txs[0];
    assert_eq!(t0["kind"], "Transfer");
    assert_eq!(
        t0["from"].as_str().unwrap().to_lowercase(),
        format!("0x{}", hex::encode(DEV_ADDR.as_slice()))
    );
    assert_eq!(t0["to"].as_str().unwrap().to_lowercase(), payee_hex);
    assert_eq!(hex_u128(&t0["value"]), 7 * UBI, "decoded value");
    // The transfer paid the 21000-gas intrinsic UBI fee.
    assert_eq!(
        hex_u128(&t0["fee"]),
        21_000u128 * 1_000_000_000u128,
        "transfer fee = gas*price"
    );
    assert_eq!(t0["call"]["kind"], "Transfer", "decoded call is a Transfer");
    assert!(
        t0["logs"].as_array().unwrap().is_empty(),
        "transfer emits no logs"
    );
    assert!(
        t0["result"].is_null(),
        "transfer has no resolvable case result"
    );

    // ubi_getTransaction returns the same decoded shape for the transfer.
    let tx = rpc(
        addr,
        "ubi_getTransaction",
        serde_json::json!([transfer_hash]),
    )
    .await;
    assert_eq!(tx["result"]["kind"], "Transfer");
    assert_eq!(hex_u128(&tx["result"]["value"]), 7 * UBI);
    println!("[expl2] transfer block + tx decoded");

    // ============================ block 2: vouchee opens a registration ============================
    // The vouchee must be a Pending registrant for a vouch to be accepted (runtime rule); it requests
    // verification first (a fee-exempt onboarding tx).
    send_ok(
        addr,
        sign_tx(
            &VOUCHEE_KEY,
            HUMANITY_HUB,
            0,
            requestVerificationCall {
                livenessRef: B256::from([0x31u8; 32]),
            }
            .abi_encode(),
            0,
        ),
    )
    .await;
    chain.produce_block(now_secs());

    // ============================ block 3: a vouch (HumanityHub) ============================
    let vouch_hash = send_ok(
        addr,
        sign_tx(
            &DEV_PRIVKEY,
            HUMANITY_HUB,
            0,
            vouchCall { vouchee: VOUCHEE }.abi_encode(),
            1,
        ),
    )
    .await;
    chain.produce_block(now_secs());

    let vtx = rpc(addr, "ubi_getTransaction", serde_json::json!([vouch_hash])).await;
    let v = &vtx["result"];
    assert_eq!(v["kind"], "Vouch");
    assert_eq!(v["call"]["hub"], "HumanityHub");
    assert_eq!(v["call"]["method"], "vouch");
    assert_eq!(
        v["call"]["args"]["vouchee"]
            .as_str()
            .unwrap()
            .to_lowercase(),
        vouchee_hex,
        "decoded vouchee arg"
    );
    assert_eq!(
        hex_u128(&v["fee"]),
        80_000u128 * 1_000_000_000u128,
        "vouch pays the humanity gas tier"
    );
    println!("[expl2] vouch tx decoded: HumanityHub.vouch(vouchee=…)");

    // ============================ block 3: deploy a contract ============================
    let deploy_hash = send_ok(
        addr,
        sign_tx(
            &DEV_PRIVKEY,
            CONTRACT_HUB,
            0,
            deployContractCall {
                text: "decoded-reads contract: pay the payee".to_string(),
                parties: vec![DEV_ADDR, PAYEE],
            }
            .abi_encode(),
            2,
        ),
    )
    .await;
    chain.produce_block(now_secs());

    let dtx = rpc(addr, "ubi_getTransaction", serde_json::json!([deploy_hash])).await;
    let d = &dtx["result"];
    assert_eq!(d["kind"], "DeployContract");
    assert_eq!(d["call"]["hub"], "ContractHub");
    assert_eq!(d["call"]["method"], "deployContract");
    assert_eq!(
        d["call"]["args"]["text"].as_str().unwrap(),
        "decoded-reads contract: pay the payee",
        "decoded full contract text"
    );
    assert_eq!(
        d["call"]["args"]["text_ref"].as_str().unwrap(),
        format!(
            "0x{}",
            hex::encode(
                alloy_primitives::keccak256(b"decoded-reads contract: pay the payee").as_slice()
            )
        ),
        "decoded text_ref = keccak256(utf8(text))"
    );
    assert_eq!(
        d["call"]["args"]["parties"].as_array().unwrap().len(),
        2,
        "two decoded parties"
    );
    // The ContractDeployed log is decoded into {name, hub, args}.
    let dlogs = d["logs"].as_array().expect("deploy logs");
    assert_eq!(dlogs.len(), 1);
    assert_eq!(dlogs[0]["name"], "ContractDeployed");
    assert_eq!(dlogs[0]["hub"], "ContractHub");
    let contract_id = dlogs[0]["args"]["id"]
        .as_u64()
        .expect("contract id from log");
    println!("[expl2] deploy tx decoded: ContractDeployed → contract #{contract_id}");

    // ============================ block 4: fund the escrow ============================
    send_ok(
        addr,
        sign_tx(
            &DEV_PRIVKEY,
            CONTRACT_HUB,
            10 * UBI,
            fundContractCall {
                id: U256::from(contract_id),
            }
            .abi_encode(),
            3,
        ),
    )
    .await;
    chain.produce_block(now_secs());

    // ============================ block 5: invoke → quorum commits the effect ============================
    let invoke_hash = send_ok(
        addr,
        sign_tx(
            &DEV_PRIVKEY,
            CONTRACT_HUB,
            0,
            invokeContractCall {
                id: U256::from(contract_id),
                triggerRef: B256::from(trigger_ref),
            }
            .abi_encode(),
            4,
        ),
    )
    .await;
    let invoke_block = chain.produce_block(now_secs());

    let itx = rpc(addr, "ubi_getTransaction", serde_json::json!([invoke_hash])).await;
    let i = &itx["result"];
    assert_eq!(i["kind"], "InvokeContract");
    assert_eq!(i["call"]["hub"], "ContractHub");
    assert_eq!(i["call"]["method"], "invokeContract");
    assert_eq!(i["call"]["args"]["id"].as_u64().unwrap(), contract_id);
    // Decoded logs: CaseOpened + EffectCommitted.
    let ilogs = i["logs"].as_array().expect("invoke logs");
    assert_eq!(
        ilogs.len(),
        2,
        "CaseOpened + EffectCommitted, got {ilogs:?}"
    );
    assert_eq!(ilogs[0]["name"], "CaseOpened");
    assert_eq!(ilogs[0]["hub"], "ContractHub");
    assert_eq!(ilogs[1]["name"], "EffectCommitted");
    let case_id = ilogs[0]["args"]["case_id"].as_u64().expect("case id");
    // The RESULTING state effect: the committed CanonicalEffect with the Transfer op.
    let result = &i["result"];
    assert_eq!(result["kind"], "ExecCase");
    assert_eq!(result["case_id"].as_u64().unwrap(), case_id);
    assert_eq!(result["contract_id"].as_u64().unwrap(), contract_id);
    assert_eq!(
        result["outcome"]["type"], "Committed",
        "the invoke committed"
    );
    let ops = result["outcome"]["effect"]["ops"]
        .as_array()
        .expect("committed effect ops");
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0]["type"], "Transfer");
    assert_eq!(
        hex_u128(&ops[0]["amount"]),
        4 * UBI,
        "committed Transfer amount"
    );
    assert_eq!(
        result["outcome"]["effect"]["effect_hash"].as_str().unwrap(),
        format!("0x{}", hex::encode(&pay4.effect_hash)),
        "the committed effect hash matches the scripted effect (I1)"
    );
    println!("[expl2] invoke tx decoded: case #{case_id} committed Transfer 4 UBI → payee");

    // ubi_getBlock(latest) and ubi_getBlock(<hash>) resolve the invoke block identically.
    let by_num = rpc(
        addr,
        "ubi_getBlock",
        serde_json::json!([format!("0x{:x}", invoke_block.number)]),
    )
    .await;
    let block_hash = by_num["result"]["hash"].as_str().unwrap().to_string();
    let by_hash = rpc(addr, "ubi_getBlock", serde_json::json!([block_hash])).await;
    assert_eq!(
        by_num["result"], by_hash["result"],
        "ubi_getBlock by number == by hash"
    );
    // The invoke block carries the decoded invoke tx (and may carry a finalize sweep tx).
    let block_txs = by_num["result"]["transactions"].as_array().unwrap();
    assert!(
        block_txs.iter().any(|t| t["kind"] == "InvokeContract"),
        "invoke block lists the decoded invoke tx"
    );

    // ubi_getBlock("latest") works as a tag too.
    let latest = rpc(addr, "ubi_getBlock", serde_json::json!(["latest"])).await;
    assert!(latest["result"]["number"]
        .as_str()
        .unwrap()
        .starts_with("0x"));

    // Unknown tx hash → null.
    let missing = rpc(
        addr,
        "ubi_getTransaction",
        serde_json::json!([format!("0x{}", "ff".repeat(32))]),
    )
    .await;
    assert!(missing["result"].is_null(), "unknown tx hash → null");

    // ubi_getAddressActivity now carries the `fee` field on each row.
    let act = rpc(
        addr,
        "ubi_getAddressActivity",
        serde_json::json!([format!("0x{}", hex::encode(DEV_ADDR.as_slice())), 10]),
    )
    .await;
    let rows = act["result"].as_array().expect("activity rows");
    assert!(!rows.is_empty());
    assert!(
        rows[0]["fee"].as_str().unwrap().starts_with("0x"),
        "activity row has fee"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
