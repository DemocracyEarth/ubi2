//! Fee-model acceptance integration test (board task: real UBI gas fee on every tx).
//!
//! Boots the real [`ubi2_rpc::serve`] HTTP+WS JSON-RPC server in-process (NON-DEFAULT port) and drives
//! it like a wallet would. Asserts the protocol's real, deterministic UBI gas fee:
//!
//!   * a **transfer**, a **vouch**, a **deploy**, and an **invoke** each pay the per-kind UBI gas fee
//!     `gas * gas_price`, and that fee lands in the reserved TREASURY (fee recycling);
//!   * value is conserved: every fee that leaves a sender is exactly the fee that enters the treasury;
//!   * **`requestVerification` (onboarding) is fee-exempt** so a zero-balance new human can register;
//!   * an account that cannot afford `value + fee` has its tx **dropped** (no state change), and the
//!     value never reaches the recipient;
//!   * `eth_estimateGas` returns the correct per-kind gas for hub calls (the MetaMask preflight fix).
//!
//! The AI seam (M3 humanity oracle, M4 interpreter) uses deterministic mocks (I5 — no model calls).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::contracts::{
    deployContractCall, derive_trigger, fundContractCall, invokeContractCall,
};
use ubi2_rpc::humanity::{requestVerificationCall, vouchCall};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{
    fee_for_gas, Account, CanonicalEffect, MockInterpreter, Op, GAS_CONTRACT, GAS_HUMANITY,
    GAS_STREAM, GAS_TRANSFER, TREASURY, UBI,
};

// Hub addresses (documented system addresses).
const STREAM_HUB: AlloyAddr = address!("0000000000000000000000000000000000005742");
const HUMANITY_HUB: AlloyAddr = address!("0000000000000000000000000000000000005048");
const CONTRACT_HUB: AlloyAddr = address!("0000000000000000000000000000000000005043");
const TREASURY_HEX: &str = "0x0000000000000000000000000000000000005542";

// Well-known PUBLIC devnet keys (Hardhat/Anvil accounts). NOT SECRETS.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

// Anvil account #1 — a verified, funded founder used as both a voucher and an interpreter/juror.
const VOUCHER2: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

// A fresh recipient/vouchee (Anvil acct #9) + its key (so it can self-register for the vouch test).
const NEWBIE: AlloyAddr = address!("a0Ee7A142d267C1f36714E4a8F75612F20a79720");
const NEWBIE_KEY: [u8; 32] =
    hex32("2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6");
// A separate recipient for the payee of a contract effect (Anvil acct #5).
const PAYEE: AlloyAddr = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");

// Anvil accounts #2/#3 — extra jurors so the registry has JURY_SIZE=3 candidates.
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

/// Async JSON-RPC-over-HTTP/1.1 client: POST one request, parse the body.
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
            let n = stream.read(&mut chunk).await.expect("read header");
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let mut body_bytes = buf.split_off(header_end);
        loop {
            let mut chunk = [0u8; 1024];
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

async fn treasury_balance(addr: SocketAddr) -> u128 {
    hex_u128(
        &rpc(
            addr,
            "eth_getBalance",
            serde_json::json!([TREASURY_HEX, "latest"]),
        )
        .await["result"],
    )
}

async fn balance_of(addr: SocketAddr, who: AlloyAddr) -> u128 {
    let h = format!("0x{}", hex::encode(who.as_slice()));
    hex_u128(&rpc(addr, "eth_getBalance", serde_json::json!([h, "latest"])).await["result"])
}

/// Boot a Chain with DEV + VOUCHER2 as funded Verified humans and three registered jurors, running a
/// deterministic interpreter that pays 5 UBI from escrow to `PAYEE` on the scripted trigger.
async fn boot(
    addr: SocketAddr,
    genesis: u64,
) -> (Chain, jsonrpsee::server::ServerHandle, [u8; 32]) {
    let trigger_ref = [0x77u8; 32];
    let trigger_bytes = derive_trigger(&trigger_ref);
    let pay5 = CanonicalEffect::new(vec![Op::Transfer {
        to: PAYEE.into_array(),
        amount: 5 * UBI,
    }]);
    let interp = Arc::new(MockInterpreter::default().with_trigger(&trigger_bytes, pay5));
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis).with_interpreter(interp);

    for k in [DEV_ADDR, VOUCHER2] {
        chain.seed_account(Account {
            address: k.into_array(),
            verified: true,
            verified_at: genesis,
            last_settled_at: genesis,
            // Prefund so a tx mined at any timestamp can cover the UBI gas fee out-of-the-box.
            settled_balance: 100 * UBI,
            nonce: 0,
        });
        chain.seed_verified_human(&k.into_array(), genesis);
    }
    for j in [VOUCHER2, JUROR2, JUROR3] {
        chain.register_juror(&j.into_array(), 0);
    }
    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(150)).await;
    (chain, handle, trigger_ref)
}

/// A transfer, a vouch, a deploy, and an invoke each pay the per-kind UBI gas fee into the TREASURY;
/// value is conserved (every fee leaving a sender enters the treasury), and onboarding is fee-exempt.
#[tokio::test]
async fn every_tx_kind_pays_a_ubi_fee_into_the_treasury() {
    let addr: SocketAddr = "127.0.0.1:18601".parse().unwrap();
    let genesis = now_secs() - 200 * 3_600; // founders hold ample emission
    let (chain, handle, trigger_ref) = boot(addr, genesis).await;

    assert_eq!(treasury_balance(addr).await, 0, "treasury starts empty");

    // ── 1. Transfer: DEV → NEWBIE 1 UBI (nonce 0). Fee = GAS_TRANSFER * price → treasury. ──
    let raw = sign_tx(&DEV_PRIVKEY, NEWBIE, UBI, Vec::new(), 0);
    send_ok(addr, raw).await;
    let mine1 = now_secs();
    chain.produce_block(mine1);

    let t_after_transfer = chain.balance(&TREASURY, mine1);
    assert_eq!(
        t_after_transfer,
        fee_for_gas(GAS_TRANSFER),
        "transfer paid exactly the transfer fee into the treasury"
    );
    // The recipient got exactly the value (the fee came on top, from the sender).
    assert_eq!(
        balance_of(addr, NEWBIE).await,
        UBI,
        "recipient received the full value; the fee was charged on top"
    );

    // NEWBIE must be a Pending registrant before it can be vouched for. It self-registers via the
    // fee-exempt onboarding path (nonce 0), so this costs the treasury nothing.
    let raw = sign_tx(
        &NEWBIE_KEY,
        HUMANITY_HUB,
        0,
        requestVerificationCall {
            livenessRef: B256::from([0x11u8; 32]),
        }
        .abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    let mine_reg = now_secs();
    chain.produce_block(mine_reg);
    assert_eq!(
        chain.balance(&TREASURY, mine_reg),
        t_after_transfer,
        "onboarding added no fee to the treasury"
    );

    // ── 2. Vouch: DEV vouches for the now-Pending NEWBIE (nonce 1). Fee = GAS_HUMANITY → treasury. ──
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        vouchCall { vouchee: NEWBIE }.abi_encode(),
        1,
    );
    send_ok(addr, raw).await;
    let mine2 = now_secs();
    chain.produce_block(mine2);

    let t_after_vouch = chain.balance(&TREASURY, mine2);
    assert_eq!(
        t_after_vouch - t_after_transfer,
        fee_for_gas(GAS_HUMANITY),
        "vouch paid exactly the humanity fee into the treasury"
    );

    // ── 3. Deploy: DEV deploys a NL contract (nonce 2). Fee = GAS_CONTRACT * price → treasury. ──
    let text_ref = B256::from([0x42u8; 32]);
    let raw = sign_tx(
        &DEV_PRIVKEY,
        CONTRACT_HUB,
        0,
        deployContractCall {
            textRef: text_ref,
            parties: vec![DEV_ADDR, PAYEE],
        }
        .abi_encode(),
        2,
    );
    let deploy_hash = send_ok(addr, raw).await;
    let mine3 = now_secs();
    chain.produce_block(mine3);

    let t_after_deploy = chain.balance(&TREASURY, mine3);
    assert_eq!(
        t_after_deploy - t_after_vouch,
        fee_for_gas(GAS_CONTRACT),
        "deploy paid exactly the contract fee into the treasury"
    );
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([deploy_hash]),
    )
    .await;
    // The receipt surfaces the per-kind gas the fee was charged on.
    assert_eq!(
        hex_u128(&receipt["result"]["gasUsed"]),
        GAS_CONTRACT as u128,
        "receipt gasUsed = contract per-kind gas"
    );
    let logs = receipt["result"]["logs"].as_array().expect("deploy logs");
    let contract_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();

    // Fund the contract escrow with 10 UBI (nonce 3) so the invoke effect can pay out.
    let raw = sign_tx(
        &DEV_PRIVKEY,
        CONTRACT_HUB,
        10 * UBI,
        fundContractCall {
            id: U256::from(contract_id),
        }
        .abi_encode(),
        3,
    );
    send_ok(addr, raw).await;
    let mine_fund = now_secs();
    chain.produce_block(mine_fund);
    let t_after_fund = chain.balance(&TREASURY, mine_fund);
    assert_eq!(
        t_after_fund - t_after_deploy,
        fee_for_gas(GAS_CONTRACT),
        "fund paid exactly the contract fee into the treasury"
    );

    // ── 4. Invoke: the interpreter quorum commits the 5 UBI Transfer (nonce 4). Fee → treasury. ──
    let raw = sign_tx(
        &DEV_PRIVKEY,
        CONTRACT_HUB,
        0,
        invokeContractCall {
            id: U256::from(contract_id),
            triggerRef: B256::from(trigger_ref),
        }
        .abi_encode(),
        4,
    );
    send_ok(addr, raw).await;
    let mine4 = now_secs();
    chain.produce_block(mine4);

    let t_after_invoke = chain.balance(&TREASURY, mine4);
    assert_eq!(
        t_after_invoke - t_after_fund,
        fee_for_gas(GAS_CONTRACT),
        "invoke paid exactly the contract fee into the treasury"
    );
    // The committed effect paid 5 UBI from escrow to the payee (the contract logic ran after the fee).
    assert_eq!(
        balance_of(addr, PAYEE).await,
        5 * UBI,
        "the invoked contract paid the payee from escrow"
    );

    // Total fees collected == sum of the per-kind fees of the five fee-bearing txs.
    let expected_fees =
        fee_for_gas(GAS_TRANSFER) + fee_for_gas(GAS_HUMANITY) + fee_for_gas(GAS_CONTRACT) * 3; // deploy + fund + invoke
    assert_eq!(
        chain.balance(&TREASURY, mine4),
        expected_fees,
        "the treasury holds exactly the sum of every tx's UBI gas fee"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// `requestVerification` is fee-exempt: a brand-new, zero-balance account can onboard, and the
/// treasury collects nothing for it (the bootstrap gate). `eth_estimateGas` reports 0 for it too, so a
/// zero-balance wallet's MetaMask preflight does not block submission.
#[tokio::test]
async fn onboarding_is_fee_exempt_and_estimates_zero() {
    let addr: SocketAddr = "127.0.0.1:18602".parse().unwrap();
    let genesis = now_secs() - 10 * 3_600;
    let (chain, handle, _) = boot(addr, genesis).await;

    // estimateGas for requestVerification (HumanityHub) is 0 — onboarding is free.
    let onboarding_data = requestVerificationCall {
        livenessRef: B256::from([0x11u8; 32]),
    }
    .abi_encode();
    let est = rpc(
        addr,
        "eth_estimateGas",
        serde_json::json!([{
            "to": format!("0x{}", hex::encode(HUMANITY_HUB.as_slice())),
            "data": format!("0x{}", hex::encode(&onboarding_data)),
        }]),
    )
    .await;
    assert_eq!(
        est["result"].as_str().unwrap(),
        "0x0",
        "onboarding estimateGas is 0 (fee-exempt)"
    );

    // A zero-balance newbie (no prefund, never verified) can still requestVerification.
    let newbie_hex = format!("0x{}", hex::encode(NEWBIE.as_slice()));
    assert_eq!(balance_of(addr, NEWBIE).await, 0, "newbie has no UBI");

    let raw = sign_tx(&NEWBIE_KEY, HUMANITY_HUB, 0, onboarding_data, 0);
    send_ok(addr, raw).await;
    let block = chain.produce_block(now_secs());
    assert_eq!(
        block.txs.len(),
        1,
        "the fee-exempt requestVerification is mined despite a zero balance"
    );
    // The treasury collected nothing for onboarding.
    assert_eq!(treasury_balance(addr).await, 0, "onboarding pays no fee");
    let human = rpc(addr, "ubi_getHuman", serde_json::json!([newbie_hex])).await;
    assert_eq!(
        human["result"]["status"], "Pending",
        "newbie is now Pending"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// An account that cannot afford `value + fee` is REJECTED AT SUBMIT (cycle-6): `eth_sendRawTransaction`
/// returns an error, the tx never enters the mempool, no value reaches the recipient, the treasury
/// collects nothing, and the sender's nonce does not advance.
///
/// NOTE — cycle-6 behavior change: the OLD contract ACCEPTED this tx at submit (the submit gate only
/// summed `value`, not the fee) and then SILENTLY DROPPED it at block time when `value + fee` couldn't
/// be paid. That drop was exactly the perpetual-pending bug — the wallet saw an accepted hash that
/// never mined. The submit affordability gate now includes the gas fee, so an un-payable tx is rejected
/// synchronously and the wallet shows an error instead. (The only remaining block-time drop is a state
/// race after submit, which is rare and still leaves no state change.)
#[tokio::test]
async fn insufficient_for_fee_is_rejected_no_state_change() {
    let addr: SocketAddr = "127.0.0.1:18603".parse().unwrap();
    let genesis = now_secs();
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis);
    // An UNVERIFIED account with EXACTLY 1 UBI settled — and unverified so it accrues NO emission, which
    // keeps the submit-time balance fixed at 1 UBI regardless of when the test runs (a verified account
    // would stream sub-second emission that could cover the fee, making this submit check flaky). It can
    // thus fund a 1 UBI value OR the fee, but never both, so the submit gate must reject `value + fee`.
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: false,
        verified_at: genesis,
        last_settled_at: genesis,
        settled_balance: UBI,
        nonce: 0,
    });
    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Send the WHOLE 1 UBI to NEWBIE; there is then nothing left for the fee → REJECTED AT SUBMIT.
    let raw = sign_tx(&DEV_PRIVKEY, NEWBIE, UBI, Vec::new(), 0);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    assert!(
        resp["result"].is_null(),
        "an un-payable (value + fee) tx must be rejected at submit, not accepted: {resp}"
    );
    let err = resp["error"]["message"].as_str().unwrap_or_default();
    assert!(
        err.contains("insufficient"),
        "rejection should explain the shortfall, got: {resp}"
    );

    // Nothing entered the mempool, so the next block is empty: no recipient, no fee, nonce stays 0.
    let mine = genesis;
    let block = chain.produce_block(mine);
    assert!(
        block.txs.is_empty(),
        "the rejected tx never entered the mempool — block is empty"
    );
    assert_eq!(
        balance_of(addr, NEWBIE).await,
        0,
        "recipient received nothing — the transfer did not run"
    );
    assert_eq!(
        chain.balance(&TREASURY, mine),
        0,
        "no fee collected for a rejected tx"
    );
    let nonce = hex_u128(
        &rpc(
            addr,
            "eth_getTransactionCount",
            serde_json::json!([format!("0x{}", hex::encode(DEV_ADDR.as_slice())), "latest"]),
        )
        .await["result"],
    );
    assert_eq!(nonce, 0, "sender nonce did not advance (no state change)");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// `eth_estimateGas` returns the correct per-kind gas for each hub (the MetaMask vouch/deploy/invoke
/// preflight fix) and the transfer intrinsic for a plain send.
#[tokio::test]
async fn estimate_gas_is_per_kind() {
    let addr: SocketAddr = "127.0.0.1:18604".parse().unwrap();
    let genesis = now_secs();
    let (_chain, handle, _) = boot(addr, genesis).await;

    let est = |to: AlloyAddr, data: Vec<u8>| {
        let h = format!("0x{}", hex::encode(to.as_slice()));
        let d = format!("0x{}", hex::encode(&data));
        async move {
            let r = rpc(
                addr,
                "eth_estimateGas",
                serde_json::json!([{ "to": h, "data": d }]),
            )
            .await;
            u64::from_str_radix(
                r["result"].as_str().unwrap().strip_prefix("0x").unwrap(),
                16,
            )
            .unwrap()
        }
    };

    // Plain transfer (to an EOA, no data) → 21000.
    assert_eq!(est(NEWBIE, Vec::new()).await, GAS_TRANSFER);
    // StreamHub call → stream gas.
    assert_eq!(est(STREAM_HUB, vec![0u8; 4]).await, GAS_STREAM);
    // HumanityHub vouch → humanity gas.
    assert_eq!(
        est(HUMANITY_HUB, vouchCall { vouchee: NEWBIE }.abi_encode()).await,
        GAS_HUMANITY
    );
    // ContractHub deploy → contract gas.
    assert_eq!(
        est(
            CONTRACT_HUB,
            deployContractCall {
                textRef: B256::ZERO,
                parties: vec![DEV_ADDR],
            }
            .abi_encode()
        )
        .await,
        GAS_CONTRACT
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
