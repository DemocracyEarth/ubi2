//! AC-WB — the byte-identical `state_root` parity gate (spec 07 §9 / §2.3, ADR-0006 Decision 3).
//!
//! Proves the browser follower (`ubi2_runtime_wasm::LightCore`) and the server follower
//! (`ubi2_rpc::Chain`) re-execute a corpus of mixed-tx-kind blocks to the **same** post-state: at every
//! height the WASM kernel's `state_root()` and `balanceOf()` equal the server's `state_root_at(h)` /
//! `eth_getBalance`-equivalent. If they ever diverged, a verifying light node could show a wrong-but-
//! "verified" balance — the worst failure this gate exists to make impossible.
//!
//! It runs on the **native** target (built `--no-default-features`, so it links only the pure
//! `LightCore` kernel with NO wasm-bindgen — the same kernel the wasm32 artifact wraps). Driving the
//! real `crates/rpc` proposer/follower as the reference is exactly what §2.3 asks: "a native-target test
//! calling the wrapper functions is acceptable to prove the kernel parity."
//!
//! It ALSO asserts the wrapper's self-contained `WireBlock` (`src/wire.rs`) decodes the CANONICAL
//! `ubi2_network::wire::WireBlock` bytes to byte-identical fields + hash + `shallow_verify` — so the
//! wire copy is provably the canonical format, not a drifting fork.

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address as AlloyAddr, Bytes, PrimitiveSignature, TxKind, U256};
use alloy_sol_types::{sol, SolCall};
use k256::ecdsa::SigningKey;

use ubi2_rpc::{Block, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, UBI};
use ubi2_runtime_wasm::wire::WireBlock as WasmWireBlock;
use ubi2_runtime_wasm::LightCore;

// The StreamHub write selectors, declared exactly as the runtime/rpc do.
sol! {
    function openStream(address to, uint256 ratePerSec, uint256 deposit) external returns (uint256 id);
    function stopStream(uint256 id) external;
}

const STREAM_HUB: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x57, 0x42,
];

/// Derive the EVM address of a secp256k1 signing key (`keccak256(uncompressed_pubkey[1..])[12..]`).
fn addr_of(sk: &SigningKey) -> [u8; 20] {
    use alloy_primitives::keccak256;
    let vk = sk.verifying_key();
    let p = vk.to_encoded_point(false);
    let h = keccak256(&p.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

/// Build a signed legacy EIP-155 tx (raw 2718 bytes, exactly what `eth_sendRawTransaction` accepts)
/// for `chain_id`, from `sk`, with the given `to` / `value` / `input` / `nonce`. The same encoding a
/// wallet produces — the server and the browser both decode it via `decode_2718`.
fn signed_tx(
    sk: &SigningKey,
    chain_id: u64,
    to: [u8; 20],
    value: u128,
    input: Vec<u8>,
    nonce: u64,
) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(chain_id),
        nonce,
        gas_price: 1_000_000_000, // 1 gwei (matches GAS_PRICE_WEI; not load-bearing for state)
        gas_limit: 1_000_000,
        to: TxKind::Call(AlloyAddr::from(to)),
        value: U256::from(value),
        input: Bytes::from(input),
    };
    let sig_hash = tx.signature_hash();
    let (sig, recid) = sk
        .sign_prehash_recoverable(sig_hash.as_slice())
        .expect("sign 32-byte prehash");
    let alloy_sig = PrimitiveSignature::from((sig, recid));
    let signed = tx.into_signed(alloy_sig);
    let env: alloy_consensus::TxEnvelope = signed.into();
    env.encoded_2718()
}

fn open_stream_calldata(to: [u8; 20], rate: u128, deposit: u128) -> Vec<u8> {
    openStreamCall {
        to: AlloyAddr::from(to),
        ratePerSec: U256::from(rate),
        deposit: U256::from(deposit),
    }
    .abi_encode()
}

fn stop_stream_calldata(id: u64) -> Vec<u8> {
    stopStreamCall { id: U256::from(id) }.abi_encode()
}

/// Map a server `rpc::Block` to the wrapper's `WireBlock` by going through the CANONICAL
/// `ubi2_network::wire::WireBlock` encode → wrapper decode. This both (a) gives the browser the exact
/// gossiped bytes a server follower would re-execute, and (b) proves the wrapper's self-contained wire
/// decode is byte-identical to the canonical one (same fields, hash, shallow_verify).
fn wire_block_for(chain: &Chain, b: &Block) -> WasmWireBlock {
    let canonical = ubi2_network::wire::WireBlock {
        number: b.number,
        parent_hash: b.parent_hash,
        timestamp: b.timestamp,
        txs_root: b.txs_root,
        state_root: b.state_root,
        proposer: b.proposer,
        proposer_sig: b.proposer_sig.clone(),
        txs: chain.raw_txs_for_block(b),
    };
    let bytes = canonical.encode();
    let decoded = WasmWireBlock::decode(&bytes).expect("wrapper decodes canonical wire bytes");

    // Byte-identity assertions: the wrapper's wire copy IS the canonical format.
    assert_eq!(decoded.number, canonical.number);
    assert_eq!(decoded.parent_hash, canonical.parent_hash);
    assert_eq!(decoded.timestamp, canonical.timestamp);
    assert_eq!(decoded.txs_root, canonical.txs_root);
    assert_eq!(decoded.state_root, canonical.state_root);
    assert_eq!(decoded.proposer, canonical.proposer);
    assert_eq!(decoded.proposer_sig, canonical.proposer_sig);
    assert_eq!(decoded.txs, canonical.txs);
    assert_eq!(
        decoded.hash(),
        canonical.hash(),
        "wrapper wire hash must equal canonical wire hash"
    );
    assert_eq!(
        decoded.shallow_verify(),
        canonical.shallow_verify(),
        "wrapper shallow_verify must equal canonical shallow_verify"
    );
    decoded
}

/// The core AC-WB corpus: a verified human (the proposer-funded dev account) sends a mix of
/// transfers + stream ops across several blocks; the WASM kernel re-executes the same blocks and must
/// match the server's `state_root` AND `balanceOf` at EVERY height.
#[test]
fn wasm_and_server_followers_agree_state_root_and_balance_for_every_block() {
    let genesis_time = 1_700_000_000u64;
    let chain_id = DEVNET_CHAIN_ID;

    // A signed-proposer chain (so blocks carry a recoverable proposer sig — the browser requires it,
    // SEC-M5A-1) and three signing accounts.
    let proposer = std::sync::Arc::new(ProposerKey::from_bytes(&[11u8; 32]).unwrap());
    let chain = Chain::new(chain_id, genesis_time).with_proposer_key(proposer);

    let alice_sk = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let bob_sk = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let carol_sk = SigningKey::from_slice(&[0x33; 32]).unwrap();
    let alice = addr_of(&alice_sk);
    let bob = addr_of(&bob_sk);
    let carol = addr_of(&carol_sk);

    // Seed Alice as a verified human with a starting balance, so emission accrues + she can fund txs.
    // (This seeding is genesis-equivalent state the light node would inherit by replaying from a
    // checkpoint; for the parity corpus we seed both followers identically by seeding the server and
    // letting the browser replay the produced blocks — see the genesis-root handling below.)
    chain.seed_verified_human(&alice, genesis_time);
    chain.seed_account(Account {
        address: alice,
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 1_000 * UBI,
        nonce: 0,
    });

    // The browser light node starts from the server's POST-SEED state root at the height it begins
    // re-executing from. In a real sync the seed would itself be committed by a block; here we anchor
    // the browser's genesis to the server's current root BEFORE producing the corpus, then replay every
    // produced block. To make the anchor a real block, produce one empty block first and start the
    // browser from it.
    let anchor = chain.produce_block(genesis_time + 2);

    // The browser's verified state must equal the server's state at the anchor height. We seed the
    // browser core's state to match by replaying from an EARLIER empty genesis is not possible (the
    // seed is not a block), so instead we construct the browser core directly at the anchor by snapshot-
    // importing the server's state — proving the snapshot round-trip too — then verify forward.
    let snap = chain.export_snapshot();
    let snap_json = serde_json::to_vec(&snap).unwrap();
    // Build the browser core at the anchor via the wrapper's own snapshot of the server state. We reuse
    // the wrapper's snapshot format by re-encoding the server state through a fresh LightCore seeded at
    // the anchor: replay every block from height anchor+1 forward, asserting parity each step. The
    // browser's anchor state_root is the server's anchor state_root by construction.
    let _ = snap_json; // (kept to document the snapshot path; the forward replay below is the gate)

    // Construct the browser core anchored at the server's anchor block, with the server's anchor STATE
    // imported (so both followers share the same parent state before the corpus). We import via the
    // wrapper's snapshot decode of a snapshot we build to match the server's anchor state.
    let mut light = build_light_at_anchor(&chain, chain_id, &anchor);

    assert_eq!(
        light.state_root(),
        anchor.state_root.0,
        "browser anchor state_root must equal server anchor state_root"
    );

    // ---- Build the corpus: a mix of tx kinds across several blocks ----
    // Block A: Alice → Bob transfer + Alice opens a stream to Carol.
    let t1 = genesis_time + 100;
    chain
        .ingest_gossip_tx(&signed_tx(&alice_sk, chain_id, bob, 5 * UBI, vec![], 0))
        .expect("alice→bob transfer admitted");
    chain
        .ingest_gossip_tx(&signed_tx(
            &alice_sk,
            chain_id,
            STREAM_HUB,
            0,
            open_stream_calldata(carol, 1_000_000_000, 10 * UBI),
            1,
        ))
        .expect("alice openStream→carol admitted");
    let block_a = chain.produce_block(t1);
    // Capture the server's per-account balances AT this height, right after producing it — before any
    // later block mutates the server state. (Reading `chain.balance` after all blocks are produced would
    // read the FINAL state, not the state at this height; the committed balance is the per-height read.)
    let bal_a = balances_at(&chain, &[alice, bob, carol], t1);

    // Block B: Bob (now funded) sends to Carol; Alice self-transfers (settles + bumps nonce).
    let t2 = genesis_time + 200;
    chain
        .ingest_gossip_tx(&signed_tx(&bob_sk, chain_id, carol, UBI, vec![], 0))
        .expect("bob→carol transfer admitted");
    chain
        .ingest_gossip_tx(&signed_tx(&alice_sk, chain_id, alice, 0, vec![], 2))
        .expect("alice self-transfer admitted");
    let block_b = chain.produce_block(t2);
    let bal_b = balances_at(&chain, &[alice, bob, carol], t2);

    // Block C: Alice stops the stream to Carol (refund path), and Carol forwards some to Bob.
    let t3 = genesis_time + 300;
    chain
        .ingest_gossip_tx(&signed_tx(
            &alice_sk,
            chain_id,
            STREAM_HUB,
            0,
            stop_stream_calldata(0),
            3,
        ))
        .expect("alice stopStream admitted");
    // Carol received stream inflow + Bob's transfer — she now has a balance to spend. Send half a UBI
    // so she comfortably covers value + the gas fee.
    chain
        .ingest_gossip_tx(&signed_tx(&carol_sk, chain_id, bob, UBI / 2, vec![], 0))
        .expect("carol→bob transfer admitted");
    let block_c = chain.produce_block(t3);
    let bal_c = balances_at(&chain, &[alice, bob, carol], t3);

    // Block D: an EMPTY block (still advances height) — the cheapest block, must also match.
    let t4 = genesis_time + 400;
    let block_d = chain.produce_block(t4);
    let bal_d = balances_at(&chain, &[alice, bob, carol], t4);
    // A live inter-block read past the tip — the browser projects the stream forward with the SAME
    // integer `Account::balance(now)` the server does (captured now, against the same final state).
    let future = t4 + 3_600;
    let bal_future = balances_at(&chain, &[alice, bob, carol], future);

    // ---- Replay every block in the browser kernel; assert parity at each height ----
    for (b, now, want) in [
        (&block_a, t1, &bal_a),
        (&block_b, t2, &bal_b),
        (&block_c, t3, &bal_c),
        (&block_d, t4, &bal_d),
    ] {
        let wire = wire_block_for(&chain, b);
        let outcome = light
            .apply_decoded(&wire, Some(b.proposer.into_array()))
            .unwrap_or_else(|e| panic!("browser must accept server block {}: {e}", b.number));

        // 1. Byte-identical state_root at this height (the I1/I2 cross-node check — AC-WB).
        assert_eq!(
            outcome.state_root, b.state_root.0,
            "state_root diverged at block {}",
            b.number
        );
        assert_eq!(
            light.state_root(),
            b.state_root.0,
            "light.state_root() must equal the header at block {}",
            b.number
        );
        assert_eq!(
            light.state_root(),
            chain
                .state_root_at(b.number)
                .expect("server has this height")
                .0,
            "light vs server state_root_at diverged at block {}",
            b.number
        );

        // 2. balanceOf parity for every account, read at this block's timestamp (the committed,
        //    consensus balance = `eth_getBalance` at this height), compared to the server's per-height
        //    capture.
        for (i, who) in [alice, bob, carol].iter().enumerate() {
            assert_eq!(
                light.balance_of(who, now).to_string(),
                want[i].to_string(),
                "balanceOf diverged for {who:?} at block {}",
                b.number
            );
        }

        // 3. The browser's nonce read is well-formed (the state_root parity above already commits every
        //    account nonce, so a divergent nonce would have failed the root check; we just exercise the
        //    accessor the browser uses to compose the next tx).
        let _ = light.nonce_of(&alice);
    }

    // The live inter-block tick agrees too: read balances at `future` against the browser's verified tip
    // state — the same integer projection the server commits.
    for (i, who) in [alice, bob, carol].iter().enumerate() {
        assert_eq!(
            light.balance_of(who, future).to_string(),
            bal_future[i].to_string(),
            "live inter-block balance projection diverged for {who:?}"
        );
    }
}

/// A forged block (mutated `state_root`) must be REJECTED by the browser kernel — the tip does not
/// advance and the lied-about balance is never adopted (AC-LC2 / AC-LC5 / AC-F-LN1). And an unsigned
/// block is never trusted (SEC-M5A-1 / AC-F-LN3).
#[test]
fn forged_and_unsigned_blocks_are_rejected() {
    let genesis_time = 1_700_000_000u64;
    let chain_id = DEVNET_CHAIN_ID;
    let proposer = std::sync::Arc::new(ProposerKey::from_bytes(&[11u8; 32]).unwrap());
    let chain = Chain::new(chain_id, genesis_time).with_proposer_key(proposer);
    let anchor = chain.produce_block(genesis_time + 2);
    let mut light = build_light_at_anchor(&chain, chain_id, &anchor);

    let good = chain.produce_block(genesis_time + 4);
    let wire = wire_block_for(&chain, &good);

    // (a) Forge the state_root: re-execution recomputes a DIFFERENT root ⇒ reject, tip unchanged.
    let mut forged = wire.clone();
    forged.state_root = alloy_primitives::B256::repeat_byte(0xff);
    let before = light.tip().number;
    let err = light.apply_decoded(&forged, Some(good.proposer.into_array()));
    assert!(err.is_err(), "a forged state_root must be rejected");
    assert_eq!(
        light.tip().number,
        before,
        "tip must not advance on a forged block"
    );

    // (b) Strip the proposer signature: an unsigned block never shallow-verifies (SEC-M5A-1).
    let mut unsigned = wire.clone();
    unsigned.proposer_sig = vec![];
    assert!(
        light
            .apply_decoded(&unsigned, Some(good.proposer.into_array()))
            .is_err(),
        "an unsigned block must be rejected (SEC-M5A-1)"
    );
    assert_eq!(
        light.tip().number,
        before,
        "tip must not advance on an unsigned block"
    );

    // (c) The GENUINE block still applies cleanly afterwards (a rejected block left no residue).
    let ok = light.apply_decoded(&wire, Some(good.proposer.into_array()));
    assert!(
        ok.is_ok(),
        "the genuine block must still apply after rejections"
    );
    assert_eq!(light.tip().number, before + 1);
    assert_eq!(light.state_root(), good.state_root.0);
}

/// The snapshot round-trip is lossless: `serialize` → `deserialize` yields a byte-identical
/// `state_root` and tip (spec §3.3, the IndexedDB persistence contract).
#[test]
fn snapshot_roundtrip_preserves_state_root_and_tip() {
    let genesis_time = 1_700_000_000u64;
    let chain_id = DEVNET_CHAIN_ID;
    let proposer = std::sync::Arc::new(ProposerKey::from_bytes(&[7u8; 32]).unwrap());
    let chain = Chain::new(chain_id, genesis_time).with_proposer_key(proposer);
    let alice_sk = SigningKey::from_slice(&[0x44; 32]).unwrap();
    let alice = addr_of(&alice_sk);
    chain.seed_verified_human(&alice, genesis_time);
    chain.seed_account(Account {
        address: alice,
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 50 * UBI,
        nonce: 0,
    });
    let anchor = chain.produce_block(genesis_time + 2);
    let mut light = build_light_at_anchor(&chain, chain_id, &anchor);

    // Apply one real block so the snapshot has non-trivial state.
    chain
        .ingest_gossip_tx(&signed_tx(
            &alice_sk,
            chain_id,
            [0xcd; 20],
            3 * UBI,
            vec![],
            0,
        ))
        .unwrap();
    let b = chain.produce_block(genesis_time + 100);
    light
        .apply_decoded(&wire_block_for(&chain, &b), Some(b.proposer.into_array()))
        .unwrap();

    let pre_root = light.state_root();
    let pre_tip = light.tip();
    let bytes = light.serialize();
    let restored = LightCore::deserialize(&bytes).expect("snapshot round-trips");
    assert_eq!(
        restored.state_root(),
        pre_root,
        "snapshot must preserve state_root"
    );
    assert_eq!(restored.tip(), pre_tip, "snapshot must preserve the tip");
    // A re-serialize is byte-stable.
    assert_eq!(
        restored.serialize(),
        bytes,
        "snapshot bytes must be stable across round-trips"
    );
}

/// Build a browser `LightCore` whose verified state EQUALS the server's state at `anchor`, by snapshot-
/// importing the server's anchor state through the wrapper's snapshot format. The browser then verifies
/// every block ABOVE the anchor by re-execution. (In production the anchor is a signed checkpoint or
/// genesis; here it lets the parity corpus share a common parent state without re-seeding the browser by
/// hand.) The constructed core's `state_root` is asserted to equal the anchor's by the callers.
fn build_light_at_anchor(chain: &Chain, chain_id: u64, anchor: &Block) -> LightCore {
    // Re-encode the server's anchor state into the wrapper's snapshot format by building a snapshot JSON
    // with the SAME field shapes the wrapper's `snapshot` module reads. We do this by serializing the
    // server snapshot's `state` section and the anchor tip into the wrapper's snapshot JSON.
    let server_snap = chain.export_snapshot();
    let server_json = serde_json::to_value(&server_snap).unwrap();
    let state = server_json
        .get("state")
        .expect("server snapshot has a state section")
        .clone();

    let light_snap = serde_json::json!({
        "version": 1,
        "chain_id": chain_id,
        "tip": {
            "number": anchor.number,
            "hash": hex32(&anchor.hash.0),
            "state_root": hex32(&anchor.state_root.0),
            "timestamp": anchor.timestamp,
        },
        "state": state,
    });
    let bytes = serde_json::to_vec(&light_snap).unwrap();
    LightCore::deserialize(&bytes).expect("browser imports the server anchor state")
}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The server's committed balances for `addrs` at `now`, captured at the CURRENT server height. Called
/// immediately after producing a block so it reads that block's state, not a later one.
fn balances_at(chain: &Chain, addrs: &[[u8; 20]], now: u64) -> Vec<u128> {
    addrs.iter().map(|a| chain.balance(a, now)).collect()
}
