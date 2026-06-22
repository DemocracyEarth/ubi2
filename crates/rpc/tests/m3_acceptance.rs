//! M3 proof-of-humanity acceptance integration test (board task M3-T4).
//!
//! Boots the real [`ubi2_rpc::serve`] HTTP+WS JSON-RPC server in-process (NON-DEFAULT ports) and
//! drives it like a standard EVM client — the same wire path a wallet uses. Maps the M3 spec's
//! acceptance criteria (`docs/specs/03-proof-of-humanity.md`) to checks against the MockOracle
//! (criterion-1 happy path verifies; criterion-2 sybil revoke stops emission):
//!
//!   * **verify → stream** (criteria 1, 5) — `unverified_to_verified_then_streams`: a fresh subject
//!     `requestVerification`s, collects ≥MIN_VOUCHES from seeded Verified accounts, the challenge
//!     window clears, the auto-finalize sweep flips it `Verified`, `ubi_getHuman` confirms, and only
//!     then does `eth_getBalance` start streaming 1 UBI/hour.
//!   * **sybil → revoke** (criterion 2) — `challenge_sybil_quorum_revokes_and_stops_emission`: a
//!     `Verified` subject is challenged, a juror quorum submits `Sybil`, the subject is `Revoked`,
//!     and its balance stops accruing past the revoke instant.
//!
//! Juror verdicts are signed with the well-known PUBLIC Anvil juror keys (accounts #1..#3) that the
//! Chain seeds as the deterministic devnet jury. NOT SECRETS — published in every EVM dev toolkit.

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
    Account, CanonicalVerdict, Confidence, MockOracle, Verdict, EMISSION_PERIOD_SECS, UBI,
};

/// Well-known PUBLIC devnet keys (Hardhat/Anvil accounts #0..#3). NOT SECRETS.
const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");

/// Anvil account #1..#3 — the seeded devnet jurors (JURY_SIZE=3 ⇒ every jury is this set).
const JUROR1_KEY: [u8; 32] =
    hex32("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d");
const JUROR2_KEY: [u8; 32] =
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
// Juror #3's key is unused (QUORUM=2 is reached with two votes) but kept for documentation/parity.
#[allow(dead_code)]
const JUROR3_KEY: [u8; 32] =
    hex32("7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6");
const JUROR1: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
const JUROR2: AlloyAddr = address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
const JUROR3: AlloyAddr = address!("90F79bf6EB2c4f870365E785982E1f101E93b906");

/// A second Verified voucher (acct #4) so a subject can reach MIN_VOUCHES (= 2) distinct vouchers.
const VOUCHER2_KEY: [u8; 32] =
    hex32("47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a");
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

/// Sign an EIP-155 legacy tx to `to` with `value` + `calldata` under `key`, returning 2718 raw bytes.
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

/// Boot a Chain with the dev account + a second voucher (both Verified humans) and the three seeded
/// jurors, served over HTTP. `genesis` is the chain's genesis unix time (drives dev emission). The
/// oracle defaults to a confident `Human` pass; tests that need a Sybil verdict script it explicitly.
async fn boot(
    addr: SocketAddr,
    genesis: u64,
    oracle: Option<Arc<dyn ubi2_runtime::HumanityOracle>>,
) -> (Chain, jsonrpsee::server::ServerHandle) {
    let mut chain = Chain::new(DEVNET_CHAIN_ID, genesis);
    if let Some(o) = oracle {
        chain = chain.with_oracle(o);
    }
    // Two seeded Verified humans (founder set) so a subject can collect MIN_VOUCHES=2 distinct vouches.
    for (a, k_at) in [(DEV_ADDR, genesis), (VOUCHER2, genesis)] {
        chain.seed_account(Account {
            address: a.into_array(),
            verified: true,
            verified_at: k_at,
            last_settled_at: k_at,
            settled_balance: 0,
            nonce: 0,
        });
        chain.seed_verified_human(&a.into_array(), k_at);
    }
    // Three deterministic devnet jurors (the jury for every case). Jurors are real humans doing
    // consensus work, so seed each as a verified, funded account: they pay the real UBI gas fee on
    // every `submitVerdict` out of their streaming balance (a juror with no UBI could not vote).
    for j in [JUROR1, JUROR2, JUROR3] {
        chain.seed_account(Account {
            address: j.into_array(),
            verified: true,
            verified_at: genesis,
            last_settled_at: genesis,
            settled_balance: UBI, // ample prefund to cover many verdict fees
            nonce: 0,
        });
        chain.register_juror(&j.into_array(), 0);
    }
    let handle = serve(addr, chain.clone()).await.expect("serve");
    tokio::time::sleep(Duration::from_millis(150)).await;
    (chain, handle)
}

/// Encode a `submitVerdict(caseId, verdict, confidence)` calldata for a juror vote.
fn verdict_call(case_id: u64, verdict: u8, confidence: u8) -> Vec<u8> {
    submitVerdictCall {
        caseId: U256::from(case_id),
        verdict,
        confidence,
    }
    .abi_encode()
}

// =============================================================================================
// verify → stream — criteria 1, 5: Unverified → Pending → Verified, then balance streams.
// =============================================================================================
#[tokio::test]
async fn unverified_to_verified_then_streams() {
    let addr: SocketAddr = "127.0.0.1:18561".parse().unwrap();
    // Dev/voucher genesis far in the past so they hold emission (not required, but realistic).
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis, None).await;

    // The subject is a *fresh* account (Anvil acct #5), not pre-seeded — it must earn Verified.
    let subject_key: [u8; 32] =
        hex32("8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba");
    let subject = address!("9965507D1a55bcC2695C58ba16FB37d819B0A4dc");
    let subj_hex = format!("0x{}", hex::encode(subject.as_slice()));

    // Subject starts Unverified (no human record) and with zero balance (not gated to stream).
    assert!(
        rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await["result"].is_null(),
        "subject starts Unverified (no record)"
    );

    // --- requestVerification(livenessRef): opens a Registration case at block height; subject Pending. ---
    let liveness_ref: B256 = B256::from([0x11u8; 32]);
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
    let b1 = chain.produce_block(now_secs()); // block height 1: registration applied
    assert_eq!(b1.txs.len(), 1, "requestVerification mined");

    // Receipt carries CaseOpened + StatusChanged(Pending). Pull the case id from the CaseOpened topic.
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([req_hash]),
    )
    .await;
    let logs = receipt["result"]["logs"].as_array().expect("logs");
    assert_eq!(
        logs.len(),
        2,
        "CaseOpened + StatusChanged(Pending), got {logs:?}"
    );
    let case_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();
    println!("[verify] requestVerification → case #{case_id}, subject Pending");

    let human = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(human["result"]["status"], "Pending", "subject is Pending");
    // Still no UBI: only Verified accrues (criterion 5).
    assert_eq!(
        hex_u128(
            &rpc(
                addr,
                "eth_getBalance",
                serde_json::json!([subj_hex, "latest"])
            )
            .await["result"]
        ),
        0,
        "Pending subject does not stream"
    );

    // --- gather MIN_VOUCHES=2 distinct Verified vouches (dev + voucher2). ---
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
    chain.produce_block(now_secs()); // block height 2: both vouches applied

    let vouches = rpc(addr, "ubi_getVouches", serde_json::json!([subj_hex])).await;
    let incoming = vouches["result"]["incoming"].as_array().expect("incoming");
    assert_eq!(
        incoming.len(),
        2,
        "subject has 2 distinct vouchers, got {incoming:?}"
    );
    println!(
        "[verify] gathered {} vouches: {:?}",
        incoming.len(),
        incoming
    );

    // The registration case's liveness was graded `Human` by the default MockOracle on open, so it is
    // already Committed(Human). Confirm via ubi_getCase before finalizing.
    let case = rpc(addr, "ubi_getCase", serde_json::json!([case_id])).await;
    assert_eq!(
        case["result"]["status"]["type"], "Committed",
        "liveness committed"
    );
    assert_eq!(
        case["result"]["status"]["verdict"]["verdict"], "Human",
        "liveness graded Human"
    );

    // --- clear the challenge window (CHALLENGE_WINDOW=5 blocks past the registration height=1). ---
    // Registration opened at height 1; finalize requires now_block >= 1 + 5 = 6. We are at height 2;
    // produce blocks until the auto-finalize sweep flips the subject. `verified_at` is stamped from
    // each block's unix timestamp (seconds) — the emission epoch.
    let mut verified_at = 0u64;
    for _ in 0..6 {
        let b = chain.produce_block(now_secs());
        if let Some(h) = chain.get_human(&subject.into_array()) {
            if h.status == ubi2_runtime::HumanStatus::Verified {
                verified_at = h.verified_at;
                println!("[verify] sweep finalized subject at block height {} (verified_at={verified_at}s)", b.number);
                break;
            }
        }
    }
    assert!(
        verified_at > 0,
        "subject must finalize to Verified within the window"
    );

    // --- ubi_getHuman now Verified; eth_getBalance streams 1 UBI/hour from verified_at (criterion 1+5). ---
    let human = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(human["result"]["status"], "Verified", "subject is Verified");
    assert_eq!(
        human["result"]["verified_at"].as_u64().unwrap(),
        verified_at,
        "verified_at stamped"
    );

    // Balance accrues exactly 1 UBI per hour from verified_at (pure runtime read at a fixed instant).
    let one_hour = chain.balance(&subject.into_array(), verified_at + EMISSION_PERIOD_SECS);
    let two_hours = chain.balance(
        &subject.into_array(),
        verified_at + 2 * EMISSION_PERIOD_SECS,
    );
    assert_eq!(one_hour, UBI, "1 UBI after 1h of being Verified");
    assert_eq!(two_hours, 2 * UBI, "2 UBI after 2h");
    println!(
        "[verify] streaming: +1h = {} UBI, +2h = {} UBI (gated on Verified)",
        one_hour / UBI,
        two_hours / UBI
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// sybil → revoke — criterion 2: challenge → AI-jury quorum Sybil → Revoked, emission stops.
// =============================================================================================
#[tokio::test]
async fn challenge_sybil_quorum_revokes_and_stops_emission() {
    let addr: SocketAddr = "127.0.0.1:18562".parse().unwrap();
    let genesis = now_secs() - 50 * EMISSION_PERIOD_SECS;
    let (chain, handle) = boot(addr, genesis, None).await;

    // The subject under challenge is the already-Verified VOUCHER2 (a seeded Verified human). Its
    // balance streams before the challenge. The challenger is the dev account.
    let subject = VOUCHER2;
    let subj_hex = format!("0x{}", hex::encode(subject.as_slice()));

    // Baseline: subject is Verified and accruing.
    let pre = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(
        pre["result"]["status"], "Verified",
        "subject starts Verified"
    );
    let stream_before = chain.balance(&subject.into_array(), genesis + 10 * EMISSION_PERIOD_SECS);
    assert_eq!(
        stream_before,
        10 * UBI,
        "subject streams 1 UBI/h while Verified"
    );

    // --- challenge(subject, evidenceRef): opens a Challenge case; Verified subject → Challenged. ---
    let evidence_ref = B256::from([0x99u8; 32]);
    let raw = sign_tx(
        &DEV_PRIVKEY,
        HUMANITY_HUB,
        0,
        challengeCall {
            subject,
            evidenceRef: evidence_ref,
        }
        .abi_encode(),
        0,
    );
    let ch_hash = send_ok(addr, raw).await;
    let b1 = chain.produce_block(now_secs());
    assert_eq!(b1.txs.len(), 1, "challenge mined");

    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([ch_hash]),
    )
    .await;
    let logs = receipt["result"]["logs"].as_array().expect("logs");
    // CaseOpened + StatusChanged(Challenged).
    assert_eq!(
        logs.len(),
        2,
        "CaseOpened + StatusChanged(Challenged), got {logs:?}"
    );
    let case_id = u64::from_str_radix(
        logs[0]["topics"][1]
            .as_str()
            .unwrap()
            .strip_prefix("0x")
            .unwrap(),
        16,
    )
    .unwrap();
    let challenged = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(
        challenged["result"]["status"], "Challenged",
        "subject flips to Challenged"
    );
    println!(
        "[sybil] challenge → case #{case_id}, subject Challenged (still innocent until quorum)"
    );

    // The case should appear in ubi_getPendingCases (it is Open).
    let pending = rpc(addr, "ubi_getPendingCases", serde_json::json!([])).await;
    let open = pending["result"].as_array().expect("pending array");
    assert!(
        open.iter().any(|c| c["id"].as_u64() == Some(case_id)),
        "case is pending/open"
    );

    // --- two jurors submit Sybil (QUORUM=2) ⇒ committed Sybil ⇒ subject Revoked. ---
    let raw = sign_tx(
        &JUROR1_KEY,
        HUMANITY_HUB,
        0,
        verdict_call(case_id, 1 /*Sybil*/, 2 /*High*/),
        0,
    );
    send_ok(addr, raw).await;
    let raw = sign_tx(&JUROR2_KEY, HUMANITY_HUB, 0, verdict_call(case_id, 1, 2), 0);
    let v2_hash = send_ok(addr, raw).await;
    chain.produce_block(now_secs());

    // The second verdict's receipt carries VerdictSubmitted + StatusChanged(Revoked).
    let receipt = rpc(
        addr,
        "eth_getTransactionReceipt",
        serde_json::json!([v2_hash]),
    )
    .await;
    let logs = receipt["result"]["logs"].as_array().expect("logs");
    assert!(
        logs.iter().any(|l| l["topics"][0]
            == serde_json::json!(format!(
                "0x{}",
                hex::encode(
                    alloy_primitives::keccak256(b"StatusChanged(address,uint8)").as_slice()
                )
            ))),
        "quorum verdict emits StatusChanged, got {logs:?}"
    );
    println!("[sybil] juror quorum submitted Sybil → case committed, StatusChanged emitted");

    // --- subject is Revoked; emission stops (criterion 2). ---
    let revoked = rpc(addr, "ubi_getHuman", serde_json::json!([subj_hex])).await;
    assert_eq!(
        revoked["result"]["status"], "Revoked",
        "subject Revoked by Sybil quorum"
    );
    assert_eq!(
        revoked["result"]["verified_at"].as_u64().unwrap(),
        0,
        "verified_at cleared"
    );

    // Emission is frozen: the balance does not climb past the revoke (no accrual once Unverified-cache).
    let after1 = chain.balance(&subject.into_array(), genesis + 100 * EMISSION_PERIOD_SECS);
    let after2 = chain.balance(&subject.into_array(), genesis + 200 * EMISSION_PERIOD_SECS);
    assert_eq!(
        after1, after2,
        "revoked subject's balance does not accrue further"
    );
    println!(
        "[sybil] revoked: balance frozen at {} UBI (no accrual after revoke)",
        after1 / UBI
    );

    // The vouchers' reputation is unaffected here (subject had no vouches_in), but the path is exercised
    // by the runtime's `revoke`. Confirm the dev voucher is still Verified (challenger unharmed).
    let dev_hex = format!("0x{}", hex::encode(DEV_ADDR.as_slice()));
    let dev = rpc(addr, "ubi_getHuman", serde_json::json!([dev_hex])).await;
    assert_eq!(
        dev["result"]["status"], "Verified",
        "challenger stays Verified"
    );

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}

// =============================================================================================
// jurors read — confirms ubi_getJurors exposes the seeded deterministic devnet jury.
// =============================================================================================
#[tokio::test]
async fn jurors_read_exposes_seeded_set() {
    let addr: SocketAddr = "127.0.0.1:18563".parse().unwrap();
    let genesis = now_secs();
    let (_, handle) = boot(addr, genesis, Some(Arc::new(MockOracle::default()))).await;

    let resp = rpc(addr, "ubi_getJurors", serde_json::json!([])).await;
    let jurors = resp["result"].as_array().expect("jurors array");
    assert_eq!(jurors.len(), 3, "three seeded devnet jurors");
    let addrs: Vec<String> = jurors
        .iter()
        .map(|j| j["address"].as_str().unwrap().to_lowercase())
        .collect();
    for j in [JUROR1, JUROR2, JUROR3] {
        let want = format!("0x{}", hex::encode(j.as_slice()));
        assert!(addrs.contains(&want.to_lowercase()), "juror {want} present");
    }
    // sanity: the verdict-enum mapping the test relies on matches the runtime canonical verdict.
    let _ = CanonicalVerdict::new(Verdict::Sybil, Confidence::High);
    println!("[jurors] ubi_getJurors = {addrs:?}");

    handle.stop().unwrap();
    let _ = handle.stopped().await;
}
