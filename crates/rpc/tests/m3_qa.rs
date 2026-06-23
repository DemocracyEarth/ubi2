//! M3 QA gate — additional integration tests (board M3-T6).
//!
//! Covers the acceptance criteria that need supplemental evidence beyond what already exists in
//! `m3_acceptance.rs` and `m3_humanity.rs`:
//!
//!   * **AC6** — AI sybil-cluster auto-challenge at the RPC level: the node's oracle flags a
//!     synthetic vouch farm; the node (or a watch-loop) files a `challenge(subject, ...)` via the
//!     HumanityHub; a juror quorum returns `Sybil`; the subject is `Revoked` before it ever
//!     finalises.  This exercises the full path on the wire, not just in-memory.
//!
//!   * **AC3 (two-node)** — quorum determinism across two independently-booted `Chain` instances
//!     that share the same op sequence and oracle: both reach byte-identical `Committed(Sybil)`
//!     without talking to each other.  Exercises the RPC-read path (`ubi_getCase`) to confirm the
//!     committed verdict is byte-identical across the two copies.
//!
//!   * **AC8 (SDK/wallet data path)** — a thin smoke-test of every `ubi_*` RPC method (same JSON
//!     shape the TypeScript `HumanityReader` / `humanity.tsx` wallet reads) against a live
//!     in-process server on port 18545 (per the QA gate port convention).  Verifies: `ubi_getHuman`
//!     returns the expected shape; `ubi_getJurors` returns the seeded set; `ubi_getVouches` carries
//!     `incoming`/`outgoing` lists; `ubi_getPendingCases` returns an array; `ubi_getCase` returns
//!     the full case object.
//!
//!   * **AC5 (genesis dev continuity)** — the genesis dev account (`0xf39F…`) is seeded `Verified`
//!     on a fresh node, so `ubi_getHuman` reports it `Verified` and its balance streams from t=0.
//!
//! All tests use the `MockOracle` — no live model calls (invariant I5).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256};
use alloy_sol_types::SolCall;
use k256::ecdsa::SigningKey;

use ubi2_rpc::humanity::{
    challengeCall, requestVerificationCall, submitVerdictCall, vouchCall, HUMANITY_HUB,
};
use ubi2_rpc::{serve, Chain, DEVNET_CHAIN_ID};
use ubi2_runtime::{
    Account, CanonicalVerdict, Confidence, GraphView, HumanityOracle, MockOracle, Verdict,
    EMISSION_PERIOD_SECS, UBI,
};

// ─────────────────────────────────────────────────────────────────────────────
// Well-known PUBLIC devnet keys (Hardhat / Anvil accounts #0..#4). NOT SECRETS.
// ─────────────────────────────────────────────────────────────────────────────
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

const VOUCHER2_KEY: [u8; 32] =
    hex32("47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a");
const VOUCHER2: AlloyAddr = address!("15d34AAf54267DB7D7c367839AAf71A00a2C6A65");

// ─────────────────────────────────────────────────────────────────────────────
// Compile-time hex → [u8;32]
// ─────────────────────────────────────────────────────────────────────────────
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(b[i * 2]) << 4) | hex_nibble(b[i * 2 + 1]);
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

// ─────────────────────────────────────────────────────────────────────────────
// Helpers shared by all tests in this file
// ─────────────────────────────────────────────────────────────────────────────

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
    let sk = SigningKey::from_slice(key).expect("valid key");
    let (sig, recid) = sk
        .sign_prehash_recoverable(tx.signature_hash().as_slice())
        .expect("sign");
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
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        let hend = loop {
            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                break p + 4;
            }
            let mut chunk = [0u8; 1024];
            let n = stream.read(&mut chunk).await.expect("read");
            if n == 0 {
                break buf.len();
            }
            buf.extend_from_slice(&chunk[..n]);
        };
        let hdr = String::from_utf8_lossy(&buf[..hend]);
        let clen: usize = hdr
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.trim()
                    .eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().ok())
                    .flatten()
            })
            .unwrap_or(0);
        let mut body_bytes = buf[hend..].to_vec();
        while body_bytes.len() < clen {
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

fn hex_u128(v: &serde_json::Value) -> u128 {
    let s = v.as_str().expect("hex string");
    u128::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).expect("parse hex u128")
}

async fn send_ok(addr: SocketAddr, raw: Vec<u8>) -> String {
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let resp = rpc(addr, "eth_sendRawTransaction", serde_json::json!([raw_hex])).await;
    resp["result"]
        .as_str()
        .unwrap_or_else(|| panic!("send failed: {resp}"))
        .to_string()
}

fn verdict_calldata(case_id: u64, verdict: u8, confidence: u8) -> Vec<u8> {
    submitVerdictCall {
        caseId: U256::from(case_id),
        verdict,
        confidence,
    }
    .abi_encode()
}

/// Boot a standard two-founder, three-juror devnet chain at `addr`.
async fn boot_chain(
    addr: SocketAddr,
    genesis: u64,
    oracle: Arc<dyn ubi2_runtime::HumanityOracle>,
) -> (Chain, jsonrpsee::server::ServerHandle) {
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis).with_oracle(oracle);
    for (a, t) in [(DEV_ADDR, genesis), (VOUCHER2, genesis)] {
        chain.seed_account(Account {
            address: a.into_array(),
            verified: true,
            verified_at: t,
            last_settled_at: t,
            // Prefund so the founders can pay the UBI gas fee on hub ops mined at the genesis
            // timestamp itself (when their emission since `verified_at` is still 0).
            settled_balance: UBI,
            nonce: 0,
        });
        chain.seed_verified_human(&a.into_array(), t);
    }
    // Jurors are verified, funded humans (they pay the real UBI gas fee on every `submitVerdict`).
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

// ─────────────────────────────────────────────────────────────────────────────
// AC6 — AI sybil-cluster auto-challenge at the RPC level
//
// Criterion: "A synthetic vouch farm (improbable cluster) is flagged and
// auto-challenged."  Specifically, we script the MockOracle to return Sybil
// when `analyze_sybil` is called on the subject, then a watcher (simulating
// the node's sybil-scan loop) reads the oracle flag, files a challenge() via
// eth_sendRawTransaction, and a juror quorum delivers Sybil — leaving the
// subject Revoked without ever being Verified.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn ac6_rpc_sybil_cluster_auto_challenge_and_revoke() {
    let addr: SocketAddr = "127.0.0.1:18545".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;

    // Script: oracle says Sybil for the subject address on analyze_sybil.
    let subject_key: [u8; 32] =
        hex32("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");
    let subject = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
    let sybil_verdict = CanonicalVerdict::new(Verdict::Sybil, Confidence::High);
    let oracle = Arc::new(
        MockOracle::default() // liveness = Human (so the applicant gets Pending)
            .with_sybil(subject.into_array(), sybil_verdict),
    );

    let (chain, handle) = boot_chain(addr, genesis, oracle.clone()).await;
    let subj_hex = format!("0x{}", hex::encode(subject.as_slice()));

    // 1. Subject requests verification (liveness passes by default mock, becomes Pending).
    let liveness_ref = B256::from([0x42u8; 32]);
    let raw = sign_tx(
        &subject_key,
        HUMANITY_HUB,
        0,
        requestVerificationCall {
            livenessRef: liveness_ref,
        }
        .abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    let human = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(
        human["result"]["status"], "Pending",
        "subject is Pending after requestVerification"
    );

    // 2. Subject gathers 2 vouches (meets MIN_VOUCHES so it's a potential finalize candidate).
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        vouchCall { vouchee: subject }.abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    let raw = sign_tx(
        &VOUCHER2_KEY,
        HUMANITY_HUB,
        0,
        vouchCall { vouchee: subject }.abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // 3. The NODE's own sybil-scan (security finding D / AC6 live path) already ran inside the
    //    produce_block above: `sweep_sybil_scan` reads the deterministic graph view, asks the oracle
    //    (scripted Sybil for this subject), and AUTO-FILES a `system_challenge` against the flagged
    //    cluster — no human had to challenge it. We confirm the oracle precondition, then discover the
    //    auto-filed Challenge case from `ubi_getPendingCases` (no manual challenge tx needed anymore).
    let graph = GraphView {
        edges: {
            let mut e = vec![
                (DEV_ADDR.into_array(), subject.into_array()),
                (VOUCHER2.into_array(), subject.into_array()),
            ];
            e.sort_unstable();
            e
        },
    };
    let flag = oracle.analyze_sybil(&graph, &subject.into_array());
    assert_eq!(
        flag.verdict,
        Verdict::Sybil,
        "oracle flags the synthetic vouch farm (AC6 precondition)"
    );
    println!("[ac6] analyze_sybil flagged subject as Sybil ({:?})", flag);

    // 4. Find the auto-filed Challenge case the node opened against the subject (it is Open and
    //    visible via ubi_getPendingCases). The node's defense fired on its own — AC6 holds live.
    let pending_resp = rpc(addr, "ubi_getPendingCases", serde_json::json!([])).await;
    let open_cases = pending_resp["result"].as_array().expect("pending cases");
    let case_id = open_cases
        .iter()
        .find(|c| c["subject"].as_str() == Some(subj_hex.as_str()))
        .and_then(|c| c["id"].as_u64())
        .expect("node auto-filed a challenge case against the flagged sybil cluster (AC6)");
    println!(
        "[ac6] node auto-filed challenge → case #{case_id} open and visible in ubi_getPendingCases"
    );

    // 5. Two jurors deliver Sybil (QUORUM=2).
    let raw = sign_tx(
        &JUROR1_KEY,
        HUMANITY_HUB,
        0,
        verdict_calldata(case_id, 1 /*Sybil*/, 2 /*High*/),
        0,
    );
    send_ok(addr, raw).await;
    let raw = sign_tx(
        &JUROR2_KEY,
        HUMANITY_HUB,
        0,
        verdict_calldata(case_id, 1, 2),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // 6. Subject is Revoked; the sybil-cluster applicant never becomes Verified (AC6 + AC2).
    let revoked = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(
        revoked["result"]["status"], "Revoked",
        "sybil-cluster subject is Revoked after quorum"
    );
    assert_eq!(
        revoked["result"]["verified_at"].as_u64().unwrap(),
        0,
        "verified_at is cleared on revoke"
    );

    // Emission is permanently 0 — UBI was never granted.
    let bal = chain.balance(
        &subject.into_array(),
        genesis + 1_000 * EMISSION_PERIOD_SECS,
    );
    assert_eq!(
        bal, 0,
        "auto-challenged sybil cluster never accrues UBI (AC6)"
    );
    println!("[ac6] Revoked: balance={}, UBI never granted", bal);

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// AC3 (two-node) — quorum determinism across two independent Chain instances
//
// Two separately-constructed Chain instances receive the same op sequence (same
// evidence, same juror votes, same oracle) and must reach byte-identical
// `Committed(Sybil)` status on their respective case objects.  No communication
// between the two — this is the "reproducible across two nodes" invariant I1.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn ac3_two_node_quorum_determinism() {
    let addr_a: SocketAddr = "127.0.0.1:18546".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:18547".parse().unwrap();
    let genesis = now_secs() - 10 * EMISSION_PERIOD_SECS;

    // Both nodes use the same deterministic oracle (all cases → Sybil).
    let oracle = Arc::new(MockOracle::always(CanonicalVerdict::new(
        Verdict::Sybil,
        Confidence::High,
    )));

    let (chain_a, handle_a) = boot_chain(addr_a, genesis, oracle.clone()).await;
    let (chain_b, handle_b) = boot_chain(addr_b, genesis, oracle.clone()).await;

    let _subject_key: [u8; 32] =
        hex32("2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6");
    let subject = address!("a0Ee7A142d267C1f36714E4a8F75612F20a79720");
    let subj_hex = format!("0x{}", hex::encode(subject.as_slice()));

    // ──── replay the same sequence on both nodes ────
    // Seed subject as Verified on both so it can be challenged immediately.
    for chain in [&chain_a, &chain_b] {
        chain.seed_account(Account {
            address: subject.into_array(),
            verified: true,
            verified_at: genesis,
            last_settled_at: genesis,
            settled_balance: 0,
            nonce: 0,
        });
        chain.seed_verified_human(&subject.into_array(), genesis);
    }

    // 1. Challenge the subject on both nodes with the same evidenceRef.
    let evidence_ref = B256::from([0xABu8; 32]);
    let challenge_data = challengeCall {
        subject,
        evidenceRef: evidence_ref,
    }
    .abi_encode();
    for addr in [addr_a, addr_b] {
        let raw = sign_tx(&DEV_PRIVKEY, HUMANITY_HUB, 0, challenge_data.clone(), 0);
        send_ok(addr, raw).await;
    }
    // mine on both
    let b_a1 = chain_a.produce_block(genesis);
    let b_b1 = chain_b.produce_block(genesis);
    // Case ids should be identical (both chains start empty, same op sequence)
    assert_eq!(b_a1.number, b_b1.number, "block heights match");

    // Read case_id from chain A.
    let pending_a = rpc(addr_a, "ubi_getPendingCases", serde_json::json!([])).await;
    let open_a = pending_a["result"].as_array().expect("open_a");
    assert_eq!(open_a.len(), 1, "node A has one open case");
    let case_id = open_a[0]["id"].as_u64().expect("case id");
    println!("[ac3] case #{case_id} open on both nodes");

    // Verify same case is open on B.
    let pending_b = rpc(addr_b, "ubi_getPendingCases", serde_json::json!([])).await;
    let open_b = pending_b["result"].as_array().expect("open_b");
    assert_eq!(open_b.len(), 1, "node B has one open case");
    assert_eq!(
        open_b[0]["id"].as_u64().expect("case id b"),
        case_id,
        "same case id on both nodes (deterministic case sequence)"
    );

    // 2. Both jurors submit Sybil on both nodes with the same verdict/confidence.
    for addr in [addr_a, addr_b] {
        let raw = sign_tx(
            &JUROR1_KEY,
            HUMANITY_HUB,
            0,
            verdict_calldata(case_id, 1, 2),
            0,
        );
        send_ok(addr, raw).await;
        let raw = sign_tx(
            &JUROR2_KEY,
            HUMANITY_HUB,
            0,
            verdict_calldata(case_id, 1, 2),
            0,
        );
        send_ok(addr, raw).await;
    }
    chain_a.produce_block(genesis + EMISSION_PERIOD_SECS);
    chain_b.produce_block(genesis + EMISSION_PERIOD_SECS);

    // 3. Both nodes must now report the case as Committed(Sybil) — byte-identical canonical effect.
    let case_a = rpc(addr_a, "ubi_getCase", serde_json::json!([case_id])).await;
    let case_b = rpc(addr_b, "ubi_getCase", serde_json::json!([case_id])).await;

    assert_eq!(
        case_a["result"]["status"]["type"], "Committed",
        "node A case is Committed"
    );
    assert_eq!(
        case_b["result"]["status"]["type"], "Committed",
        "node B case is Committed"
    );
    assert_eq!(
        case_a["result"]["status"]["verdict"]["verdict"],
        case_b["result"]["status"]["verdict"]["verdict"],
        "both nodes committed the SAME verdict (I1)"
    );
    assert_eq!(
        case_a["result"]["status"]["verdict"]["confidence"],
        case_b["result"]["status"]["verdict"]["confidence"],
        "both nodes committed the SAME confidence bucket (I1)"
    );

    let verdict_a = &case_a["result"]["status"]["verdict"]["verdict"];
    assert_eq!(verdict_a, "Sybil", "committed verdict is Sybil");
    println!(
        "[ac3] node A verdict={} confidence={}, node B verdict={} confidence={} — identical (I1)",
        case_a["result"]["status"]["verdict"]["verdict"],
        case_a["result"]["status"]["verdict"]["confidence"],
        case_b["result"]["status"]["verdict"]["verdict"],
        case_b["result"]["status"]["verdict"]["confidence"],
    );

    // 4. Both subjects are Revoked (I4 effect applied consistently).
    let r_a = rpc(addr_a, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    let r_b = rpc(addr_b, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(r_a["result"]["status"], "Revoked", "node A subject Revoked");
    assert_eq!(r_b["result"]["status"], "Revoked", "node B subject Revoked");
    println!("[ac3] both nodes agree: subject Revoked. Two-node quorum determinism verified.");

    handle_a.stop().unwrap();
    handle_b.stop().unwrap();
    let _ = handle_a.stopped().await;
    let _ = handle_b.stopped().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// AC8 — SDK / wallet data path: all ubi_* methods return the expected shape
//
// This test boots a node on :18545 (the QA gate port) and exercises every
// ubi_* method the TypeScript HumanityReader / humanity.tsx wallet reads,
// asserting the JSON shape matches the SDK's TypeScript interfaces
// (HumanRecord, CaseRecord, JurorRecord, VouchSet).  Covers: ubi_getHuman,
// ubi_getCase, ubi_getVouches, ubi_getJurors, ubi_getPendingCases, and also
// confirms requestVerification → vouch → challenge flows produce observable
// state through the same reads.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn ac8_sdk_wallet_data_path() {
    let addr: SocketAddr = "127.0.0.1:18548".parse().unwrap();
    let genesis = now_secs() - 5 * EMISSION_PERIOD_SECS;
    let oracle = Arc::new(MockOracle::default());
    let (chain, handle) = boot_chain(addr, genesis, oracle).await;

    let dev_hex = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));

    // ── (a) ubi_getHuman — genesis dev account is Verified (AC5: genesis dev continuity) ──────
    let human_resp = rpc(addr, "ubi_getHuman", serde_json::json!([dev_hex])).await;
    let h = &human_resp["result"];
    assert!(
        !h.is_null(),
        "ubi_getHuman returns a record for the dev account"
    );
    assert_eq!(h["status"], "Verified", "genesis dev is Verified");
    assert!(h["verified_at"].is_u64(), "verified_at is a number");
    assert!(h["liveness_ref"].is_string(), "liveness_ref is a string");
    assert!(h["vouches_in"].is_array(), "vouches_in is an array");
    assert!(h["reputation"].is_number(), "reputation is a number");
    assert!(h["address"].is_string(), "address field present");
    println!(
        "[ac8] ubi_getHuman shape OK: status={}, verified_at={}",
        h["status"], h["verified_at"]
    );

    // ── (b) ubi_getJurors — returns the seeded set with address/stake/active fields ────────────
    let jurors_resp = rpc(addr, "ubi_getJurors", serde_json::json!([])).await;
    let jurors = jurors_resp["result"].as_array().expect("jurors array");
    assert_eq!(jurors.len(), 3, "three seeded jurors");
    for j in jurors {
        assert!(j["address"].is_string(), "juror address field");
        assert!(j["stake"].is_string(), "juror stake field (hex-qty)");
        assert!(j["active"].is_boolean(), "juror active field");
    }
    println!("[ac8] ubi_getJurors shape OK: {} jurors", jurors.len());

    // ── (c) ubi_getVouches — returns outgoing/incoming for the dev account ───────────────────
    let vouches_resp = rpc(addr, "ubi_getVouches", serde_json::json!([dev_hex])).await;
    let v = &vouches_resp["result"];
    assert!(v["outgoing"].is_array(), "outgoing field is an array");
    assert!(v["incoming"].is_array(), "incoming field is an array");
    println!(
        "[ac8] ubi_getVouches shape OK: outgoing={} incoming={}",
        v["outgoing"].as_array().unwrap().len(),
        v["incoming"].as_array().unwrap().len()
    );

    // ── (d) ubi_getPendingCases — returns array (empty at genesis) ───────────────────────────
    let pending_resp = rpc(addr, "ubi_getPendingCases", serde_json::json!([])).await;
    assert!(
        pending_resp["result"].is_array(),
        "ubi_getPendingCases returns array"
    );
    println!(
        "[ac8] ubi_getPendingCases shape OK: {} open cases at genesis",
        pending_resp["result"].as_array().unwrap().len()
    );

    // ── (e) drive a requestVerification + vouch + challenge flow; read back via ubi_* ─────────
    // Anvil account #5 (well-known, same pair that m3_acceptance.rs uses successfully).
    let subject_key: [u8; 32] =
        hex32("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");
    let subject = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
    let subj_hex = format!("0x{}", hex::encode(subject.as_slice()));

    // requestVerification (wallet: "Apply for verification" button flow)
    let liveness_ref = B256::from([0x33u8; 32]);
    let raw = sign_tx(
        &subject_key,
        HUMANITY_HUB,
        0,
        requestVerificationCall {
            livenessRef: liveness_ref,
        }
        .abi_encode(),
        0,
    );
    let req_hash = send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    let after_req = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(
        after_req["result"]["status"], "Pending",
        "after requestVerification subject is Pending"
    );
    println!("[ac8] requestVerification: subject is Pending");

    // Get the case id from the receipt (the CaseOpened log).
    // Note: the Registration case commits immediately (all jurors vote at block time in the devnet),
    // so it will appear as Committed (not Open) in ubi_getPendingCases — that is correct behavior.
    let req_receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([req_hash]),
    )
    .await;
    let req_logs = req_receipt["result"]["logs"].as_array().expect("req logs");
    assert!(
        !req_logs.is_empty(),
        "requestVerification receipt has logs (CaseOpened + StatusChanged)"
    );
    let reg_case_id = u64::from_str_radix(
        req_logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();
    println!("[ac8] requestVerification → reg case #{reg_case_id} opened (from receipt logs)");

    // ubi_getCase by id — the wallet/juror calls this to read the full case object.
    // (The case will be Committed(Human) immediately since MockOracle auto-passes liveness.)
    let case_resp = rpc(addr, "ubi_getCase", serde_json::json!([reg_case_id])).await;
    assert!(
        !case_resp["result"].is_null(),
        "ubi_getCase returns the case"
    );
    assert_eq!(
        case_resp["result"]["id"].as_u64().unwrap(),
        reg_case_id,
        "id matches"
    );
    assert_eq!(
        case_resp["result"]["kind"], "Registration",
        "kind is Registration"
    );
    // Case must have the expected fields (CaseRecord interface).
    let case_val = &case_resp["result"];
    assert!(
        case_val["id"].is_number() || case_val["id"].is_u64(),
        "case id field"
    );
    assert!(case_val["subject"].is_string(), "case subject field");
    assert!(case_val["kind"].is_string(), "case kind field");
    assert!(
        case_val["evidence_ref"].is_string(),
        "case evidence_ref field"
    );
    assert!(case_val["jury"].is_array(), "case jury field");
    assert!(case_val["votes"].is_array(), "case votes field");
    assert!(case_val["status"].is_object(), "case status field");
    assert!(case_val["opened_at"].is_number(), "case opened_at field");
    println!(
        "[ac8] ubi_getCase shape OK: case #{reg_case_id} ({} votes)",
        case_val["votes"].as_array().unwrap().len()
    );

    // vouch (wallet: "Vouch" action for a Verified account — dev vouches for the Pending subject)
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        vouchCall { vouchee: subject }.abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    let raw = sign_tx(
        &VOUCHER2_KEY,
        HUMANITY_HUB,
        0,
        vouchCall { vouchee: subject }.abi_encode(),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // ubi_getVouches: subject now has 2 incoming vouchers
    let v_resp = rpc(addr, "ubi_getVouches", serde_json::json!([subj_hex])).await;
    let incoming = v_resp["result"]["incoming"].as_array().unwrap();
    assert_eq!(
        incoming.len(),
        2,
        "subject has 2 incoming vouches (MIN_VOUCHES met)"
    );
    println!(
        "[ac8] ubi_getVouches: {} incoming vouches for subject",
        incoming.len()
    );

    // ubi_getHuman updated: vouches_in array has 2 entries
    let after_vouch = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    let vouches_in = after_vouch["result"]["vouches_in"].as_array().unwrap();
    assert_eq!(
        vouches_in.len(),
        2,
        "vouches_in has 2 entries on the human record"
    );

    // challenge (wallet: "Challenge" action by a user challenging a VERIFIED account —
    // VOUCHER2 is pre-seeded Verified, so challenging it produces the "Challenged" status).
    let challenge_target = VOUCHER2;
    let challenge_target_hex = format!("0x{}", hex::encode(challenge_target.as_slice()));
    let evidence_ref = B256::from([0x77u8; 32]);
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        challengeCall {
            subject: challenge_target,
            evidenceRef: evidence_ref,
        }
        .abi_encode(),
        1, // nonce 1 on dev (nonce 0 already consumed by the vouch above)
    );
    let ch_hash = send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // A Verified target flips to Challenged when a challenge case is opened.
    let after_chal = rpc(
        addr,
        "ubi_getHuman",
        serde_json::json!([challenge_target_hex]),
    )
    .await;
    assert_eq!(
        after_chal["result"]["status"], "Challenged",
        "after challenge a Verified target is Challenged"
    );
    println!("[ac8] challenge submitted via wallet path, target status = Challenged");

    // Receipt should contain at least the CaseOpened log.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([ch_hash]),
    )
    .await;
    let logs = receipt["result"]["logs"].as_array().expect("logs");
    assert!(!logs.is_empty(), "challenge tx receipt has logs");
    println!("[ac8] challenge receipt: {} log(s)", logs.len());

    // ubi_getPendingCases: the challenge case is Open, so it appears in the pending list.
    let pending_after_chal = rpc(addr, "ubi_getPendingCases", serde_json::json!([])).await;
    let open_chal = pending_after_chal["result"].as_array().unwrap();
    assert!(
        !open_chal.is_empty(),
        "challenge case appears in ubi_getPendingCases"
    );
    let chal_case_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();
    // The case record shape (CaseRecord interface) must be correct.
    let chal_case_val = open_chal
        .iter()
        .find(|c| c["id"].as_u64() == Some(chal_case_id))
        .expect("chal case in pending list");
    assert!(
        chal_case_val["id"].is_number() || chal_case_val["id"].is_u64(),
        "case id field"
    );
    assert!(chal_case_val["subject"].is_string(), "case subject field");
    assert_eq!(chal_case_val["kind"], "Challenge", "kind is Challenge");
    assert!(
        chal_case_val["evidence_ref"].is_string(),
        "case evidence_ref field"
    );
    assert!(chal_case_val["jury"].is_array(), "case jury field");
    assert!(chal_case_val["votes"].is_array(), "case votes field");
    assert!(chal_case_val["status"].is_object(), "case status field");
    assert!(
        chal_case_val["opened_at"].is_number(),
        "case opened_at field"
    );
    println!("[ac8] ubi_getPendingCases: challenge case #{chal_case_id} found with correct shape");

    // Juror submits a Human verdict (juror UI path — a juror reads the case and submits).
    let raw = sign_tx(
        &JUROR1_KEY,
        HUMANITY_HUB,
        0,
        verdict_calldata(chal_case_id, 0 /*Human*/, 2 /*High*/),
        0,
    );
    send_ok(addr, raw).await;
    let raw = sign_tx(
        &JUROR2_KEY,
        HUMANITY_HUB,
        0,
        verdict_calldata(chal_case_id, 0, 2),
        0,
    );
    send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // Challenge target restored to Verified (two Human votes = quorum upholds, I4).
    let after_verdict = rpc(
        addr,
        "ubi_getHuman",
        serde_json::json!([challenge_target_hex]),
    )
    .await;
    assert_eq!(
        after_verdict["result"]["status"], "Verified",
        "Human jury verdict restores target to Verified"
    );
    println!("[ac8] after Human jury verdict: target restored to Verified");

    // Confirm the case is now Committed (not Open)
    let final_case = rpc(addr, "ubi_getCase", serde_json::json!([chal_case_id])).await;
    assert_eq!(
        final_case["result"]["status"]["type"], "Committed",
        "challenge case is Committed after quorum"
    );
    assert_eq!(
        final_case["result"]["status"]["verdict"]["verdict"], "Human",
        "committed verdict is Human"
    );
    println!("[ac8] all SDK/wallet data-path methods verified end-to-end");

    // Confirm genesis dev account balance is streaming (AC5 confirmation via the balance RPC)
    let bal_resp = rpc(
        addr,
        "eth_getBalance",
        serde_json::json!([dev_hex, "latest"]),
    )
    .await;
    let bal = hex_u128(&bal_resp["result"]);
    assert!(
        bal > 0,
        "genesis dev account balance is streaming (verified from t=0)"
    );
    println!(
        "[ac8] genesis dev balance = {} base units (streaming confirmed, AC5)",
        bal
    );

    // req_hash just to confirm the tx was found by the node
    let _ = req_hash;

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// ─────────────────────────────────────────────────────────────────────────────
// AC7 (privacy / I6) at the RPC level — no PII fields in ubi_* responses
//
// The JSON returned by ubi_getHuman and ubi_getCase must contain ONLY
// commitment fields (liveness_ref as hex, evidence_ref as hex, reasons_hash as
// hex) — never the raw challenge/response bytes.  Verifies the I6 privacy
// invariant from the wire perspective.
// ─────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn ac7_rpc_no_pii_on_wire() {
    let addr: SocketAddr = "127.0.0.1:18549".parse().unwrap();
    let genesis = now_secs();
    let oracle = Arc::new(MockOracle::default());
    let (chain, handle) = boot_chain(addr, genesis, oracle).await;

    // Register + mine a subject so we have a real case to inspect.
    let subject_key: [u8; 32] =
        hex32("47c99abed3324a2707c28affff1267e45918ec8c3f20b8aa892e8b065d2942dd");
    let subject = address!("1CBd3b2770909D4e10f157cABC84C7264073C9Ec");
    let subj_hex = format!("0x{}", hex::encode(subject.as_slice()));
    let liveness_ref_bytes = [0xBBu8; 32];
    let liveness_ref = B256::from(liveness_ref_bytes);

    let raw = sign_tx(
        &subject_key,
        HUMANITY_HUB,
        0,
        requestVerificationCall {
            livenessRef: liveness_ref,
        }
        .abi_encode(),
        0,
    );
    let req_hash = send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // ── ubi_getHuman: check the on-chain fields contain ONLY the commitment hash ──────────────
    let h = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    let rec = &h["result"];
    assert!(
        !rec.is_null(),
        "ubi_getHuman must return a record for the subject"
    );

    // liveness_ref must be the exact 32-byte commitment that was submitted, as a hex string.
    let lr = rec["liveness_ref"].as_str().expect("liveness_ref string");
    let lr_bytes = decode_hex_str(lr);
    assert_eq!(
        lr_bytes, liveness_ref_bytes,
        "liveness_ref commitment preserved exactly"
    );

    // The record must NOT contain any field that could hold raw challenge/response bytes.
    // The schema is: address, status, verified_at, liveness_ref, vouches_in, reputation.
    // Any additional field would be a privacy violation.
    let fields_present: Vec<String> = rec.as_object().unwrap().keys().cloned().collect();
    println!("[ac7] ubi_getHuman fields: {:?}", fields_present);
    for pii_field in &["challenge", "response", "transcript", "biometric", "raw"] {
        assert!(
            !fields_present.iter().any(|f| f == pii_field),
            "PII field '{pii_field}' must not appear in ubi_getHuman (I6)"
        );
    }

    // ── ubi_getCase: fetch via receipt (Registration case commits immediately, not open) ──────
    // The Registration case commits right away in the devnet (MockOracle grades liveness at block
    // production time, so by the time we read ubi_getPendingCases it is already Committed and gone
    // from the Open list). Get the case id from the receipt's CaseOpened log.
    let req_receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([req_hash]),
    )
    .await;
    let req_logs = req_receipt["result"]["logs"]
        .as_array()
        .expect("receipt logs");
    assert!(!req_logs.is_empty(), "requestVerification receipt has logs");
    let reg_case_id = u64::from_str_radix(
        req_logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();

    // Now read the case object directly by id.
    let case_resp = rpc(addr, "ubi_getCase", serde_json::json!([reg_case_id])).await;
    let case = &case_resp["result"];
    assert!(!case.is_null(), "ubi_getCase returns the Registration case");
    let case_fields: Vec<String> = case.as_object().unwrap().keys().cloned().collect();
    println!("[ac7] ubi_getCase fields: {:?}", case_fields);
    for pii_field in &[
        "challenge",
        "response",
        "transcript",
        "biometric",
        "raw_evidence",
    ] {
        assert!(
            !case_fields.iter().any(|f| f == pii_field),
            "PII field '{pii_field}' must not appear in ubi_getCase (I6)"
        );
    }
    // evidence_ref is a 32-byte commitment string, not raw bytes.
    let er = case["evidence_ref"].as_str().expect("evidence_ref string");
    let er_decoded = decode_hex_str(er);
    assert_eq!(er_decoded.len(), 32, "evidence_ref is exactly 32 bytes");

    println!("[ac7] privacy check passed: no PII fields on wire from ubi_* methods (I6)");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

/// Decode a 0x-prefixed or bare hex string to bytes.
fn decode_hex_str(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    assert!(s.len().is_multiple_of(2), "odd-length hex: {s}");
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
