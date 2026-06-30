//! ln-trust — the pinned, gateway-independent genesis anchor + always-on proposer authority gate
//! (spec 07 §3.4; closes findings `ln-trust-1`/`ln-trust-2`/`ln-trust-3`).
//!
//! These tests prove the three guarantees the fix adds on top of the AC-WB parity gate:
//!
//!   (a) `rejects_gateway_with_wrong_pinned_anchor` — a gateway that serves a genesis snapshot whose
//!       re-derived `state_root` != the PINNED constant is REJECTED (`GenesisRootMismatch`). The lying
//!       gateway never gets the client to anchor on its own genesis (`ln-trust-2`/`ln-trust-3`).
//!
//!   (b) `rejects_block_from_proposer_not_in_pinned_set` — once a PoA validator set is pinned, a block
//!       whose proposer is NOT in it is REJECTED on EVERY block, with NO None-skip (`ln-trust-1`). A
//!       self-consistent chain a malicious gateway signed with ITS OWN key is caught, not "verified".
//!
//!   (c) `reproduces_real_seeded_genesis_chain` — the client imports the gateway's seeded genesis
//!       snapshot (accounts + a verified human + jurors + a CSCA registry + governance), re-derives its
//!       `state_root`, verifies it equals the honest gateway's sealed seeded root, then re-executes
//!       block #1+ to a state_root byte-identical to the honest gateway through every height. This is the
//!       product working on a REAL seeded chain (the empty-state import was non-functional: `ln-trust-2`).
//!
//! Built on the NATIVE target (`--no-default-features`, like `tests/parity.rs`): it links only the pure
//! `LightCore` kernel + the real `crates/rpc::Chain` as the honest gateway/proposer reference.

use alloy_consensus::{SignableTransaction, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address as AlloyAddr, Bytes, PrimitiveSignature, TxKind, U256};
use k256::ecdsa::SigningKey;

use ubi2_rpc::{Block, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::{Account, UBI};
use ubi2_runtime_wasm::wire::WireBlock as WasmWireBlock;
use ubi2_runtime_wasm::LightCore;

// ---------------------------------------------------------------------------------------------
// Helpers (shared with the parity test's patterns; kept self-contained here).
// ---------------------------------------------------------------------------------------------

fn addr_of(sk: &SigningKey) -> [u8; 20] {
    use alloy_primitives::keccak256;
    let vk = sk.verifying_key();
    let p = vk.to_encoded_point(false);
    let h = keccak256(&p.as_bytes()[1..]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..]);
    a
}

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
        gas_price: 1_000_000_000,
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

/// Map a server `rpc::Block` to the wrapper's `WireBlock` through the CANONICAL `ubi2_network` wire bytes
/// (the exact bytes the sync gateway serves), so the light client re-executes the gossiped block.
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
    WasmWireBlock::decode(&canonical.encode()).expect("wrapper decodes canonical wire bytes")
}

/// Seed the canonical devnet-style genesis onto a fresh chain: a pre-verified dev account that streams
/// UBI, a couple of registered jurors, and a CSCA trust-anchor + governance (so the genesis state_root
/// folds a NON-EMPTY accounts/humans/jurors/CSCA registry — exactly the real seeded genesis the empty
/// import could not reproduce).
fn seed_genesis(chain: &Chain, dev: [u8; 20], jurors: &[[u8; 20]], genesis_time: u64) {
    chain.seed_verified_human(&dev, genesis_time);
    chain.seed_account(Account {
        address: dev,
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 1_000 * UBI,
        nonce: 0,
    });
    for j in jurors {
        chain.register_juror(j, 0);
    }
    chain.set_csca_governance(&dev);
    chain.seed_csca(*b"USA", [0xC5; 32], vec![0xCA, 0xFE, 0xBA, 0xBE]);
}

/// Build the light client from a chain's SEALED genesis anchor, exactly as the shipped app does:
/// `genesis_import(pinned_hash, pinned_root, snapshot, validator_set)`. Returns the verified `LightCore`.
fn import_from_anchor(chain: &Chain, validator_set: Vec<[u8; 20]>) -> LightCore {
    let anchor = chain
        .genesis_anchor()
        .expect("the honest gateway sealed its genesis anchor");
    LightCore::genesis_import(
        DEVNET_CHAIN_ID,
        chain.genesis_hash().0,
        anchor.state_root.0,
        chain.genesis_time(),
        &anchor.snapshot,
        validator_set,
    )
    .expect("client imports the verified seeded genesis")
}

// ---------------------------------------------------------------------------------------------
// (a) A gateway whose genesis snapshot re-derives to a root != the PINNED constant is REJECTED.
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_gateway_with_wrong_pinned_anchor() {
    let genesis_time = 1_700_000_000u64;
    let proposer = std::sync::Arc::new(ProposerKey::from_bytes(&[11u8; 32]).unwrap());

    // The HONEST chain the app pinned its constants against.
    let dev = addr_of(&SigningKey::from_slice(&[0x11; 32]).unwrap());
    let jurors = [
        addr_of(&SigningKey::from_slice(&[0x21; 32]).unwrap()),
        addr_of(&SigningKey::from_slice(&[0x22; 32]).unwrap()),
    ];
    let honest = Chain::new(DEVNET_CHAIN_ID, genesis_time).with_proposer_key(proposer.clone());
    seed_genesis(&honest, dev, &jurors, genesis_time);
    honest.seal_genesis();
    let pinned = honest.genesis_anchor().unwrap();
    let pinned_root = pinned.state_root.0;
    let pinned_hash = honest.genesis_hash().0;

    // A MALICIOUS gateway serving a DIFFERENT seeded genesis (an extra rich account — a self-consistent
    // chain from the gateway's own genesis). Its snapshot re-derives to a different root.
    let evil = Chain::new(DEVNET_CHAIN_ID, genesis_time).with_proposer_key(proposer);
    let attacker = addr_of(&SigningKey::from_slice(&[0x99; 32]).unwrap());
    seed_genesis(&evil, dev, &jurors, genesis_time);
    evil.seed_account(Account {
        address: attacker,
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 1_000_000 * UBI, // the attacker mints itself a fortune at genesis
        nonce: 0,
    });
    evil.seal_genesis();
    let evil_anchor = evil.genesis_anchor().unwrap();
    assert_ne!(
        evil_anchor.state_root.0, pinned_root,
        "the evil gateway's seeded genesis must differ from the pinned one"
    );

    // The client imports the EVIL gateway's snapshot but verifies it against the PINNED root → REJECTED.
    let err = LightCore::genesis_import(
        DEVNET_CHAIN_ID,
        pinned_hash,
        pinned_root, // the app's hard-coded constant
        genesis_time,
        &evil_anchor.snapshot, // the lying gateway's data
        vec![proposer_addr_of(&[11u8; 32])],
    )
    .err();
    assert!(
        matches!(
            err,
            Some(ubi2_runtime_wasm::VerifyError::GenesisRootMismatch { .. })
        ),
        "a gateway whose seeded genesis != the pinned root must be rejected, got {err:?}"
    );

    // And the HONEST gateway's snapshot, against the SAME pinned root, imports cleanly.
    let ok = LightCore::genesis_import(
        DEVNET_CHAIN_ID,
        pinned_hash,
        pinned_root,
        genesis_time,
        &pinned.snapshot,
        vec![proposer_addr_of(&[11u8; 32])],
    )
    .expect("the honest gateway's snapshot must import against its own pinned root");
    // ln-trust-3: the imported state's root equals the pinned constant (never the all-zeros default).
    assert_eq!(ok.state_root(), pinned_root);
}

// ---------------------------------------------------------------------------------------------
// (b) A block whose proposer is NOT in the pinned validator set is REJECTED — on every block, no skip.
// ---------------------------------------------------------------------------------------------

#[test]
fn rejects_block_from_proposer_not_in_pinned_set() {
    let genesis_time = 1_700_000_000u64;

    // The AUTHORIZED PoA proposer (the pinned validator set is exactly this one key on the devnet).
    let authorized = std::sync::Arc::new(ProposerKey::from_bytes(&[11u8; 32]).unwrap());
    let authorized_addr = authorized.address().into_array();

    let dev = addr_of(&SigningKey::from_slice(&[0x11; 32]).unwrap());
    let jurors = [addr_of(&SigningKey::from_slice(&[0x21; 32]).unwrap())];

    let chain = Chain::new(DEVNET_CHAIN_ID, genesis_time).with_proposer_key(authorized.clone());
    seed_genesis(&chain, dev, &jurors, genesis_time);
    chain.seal_genesis();

    // The client pins the validator set = { authorized } (the app's hard-coded PoA set).
    let mut light = import_from_anchor(&chain, vec![authorized_addr]);

    // A genuine block from the AUTHORIZED proposer applies (even when `expected_proposer` is None — the
    // pinned set is enforced regardless, AND a scheduled-proposer pin still works).
    let good = chain.produce_block(genesis_time + 10);
    let good_wire = wire_block_for(&chain, &good);
    assert!(
        light.apply_decoded(&good_wire, None).is_ok(),
        "an authorized-proposer block must be accepted with no None-skip vulnerability"
    );
    assert_eq!(light.tip().number, 1);

    // Now the ATTACKER gateway serves a self-consistent block #2 that links to the client's tip but is
    // signed with ITS OWN key (a different, unauthorized proposer). We take the HONEST block #2 (so its
    // `parent_hash` matches the client's tip + its `state_root`/txs are valid) and RE-PROPOSE it under
    // the attacker's key: a fresh header hash + a valid attacker signature. `shallow_verify` passes (the
    // sig recovers to the stamped proposer) and the root would match — but the proposer ∉ the pinned set.
    let honest_b2 = chain.produce_block(genesis_time + 20);
    let attacker_key = ProposerKey::from_bytes(&[0x77; 32]).unwrap();
    let evil_wire = repropose_under(&wire_block_for(&chain, &honest_b2), &[0x77; 32]);
    assert!(
        evil_wire.shallow_verify(),
        "the re-proposed evil block must shallow-verify (valid sig over its own proposer)"
    );
    assert_eq!(
        evil_wire.proposer.into_array(),
        attacker_key.address().into_array(),
        "the evil block's proposer is the attacker's address"
    );
    assert_eq!(
        evil_wire.parent_hash.0,
        light.tip().hash,
        "the evil block links to the client's verified tip (so it is not a WrongParent reject)"
    );

    let before = light.tip().number;
    // Even passing `None` for expected_proposer (the exact None-skip the finding describes), the pinned
    // validator-set enforcement REJECTS the unauthorized proposer.
    let err = light.apply_decoded(&evil_wire, None);
    assert!(
        matches!(
            err,
            Err(ubi2_runtime_wasm::VerifyError::UnauthorizedProposer { .. })
        ),
        "a block from a proposer not in the pinned set must be rejected (no None-skip), got {err:?}"
    );
    assert_eq!(
        light.tip().number,
        before,
        "the tip must not advance on an unauthorized-proposer block"
    );

    // The GENUINE block #2 (from the authorized proposer — the same `honest_b2` the attacker forged from)
    // still applies cleanly afterwards: the rejected evil block left no residue, and the authorized
    // proposer is in the pinned set.
    let good2_wire = wire_block_for(&chain, &honest_b2);
    assert!(
        light
            .apply_decoded(&good2_wire, Some(authorized_addr))
            .is_ok(),
        "the authorized proposer's genuine block #2 must still apply"
    );
    assert_eq!(light.tip().number, 2);
}

// ---------------------------------------------------------------------------------------------
// (c) The client reproduces a REAL seeded-genesis chain: verified snapshot import → state_root matches
//     an honest gateway through block #1+, where genesis seeds accounts/jurors/CSCA.
// ---------------------------------------------------------------------------------------------

#[test]
fn reproduces_real_seeded_genesis_chain() {
    let genesis_time = 1_700_000_000u64;
    let chain_id = DEVNET_CHAIN_ID;
    let proposer = std::sync::Arc::new(ProposerKey::from_bytes(&[11u8; 32]).unwrap());
    let proposer_addr = proposer.address().into_array();

    let dev_sk = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let bob_sk = SigningKey::from_slice(&[0x22; 32]).unwrap();
    let dev = addr_of(&dev_sk);
    let bob = addr_of(&bob_sk);
    let jurors = [
        addr_of(&SigningKey::from_slice(&[0x31; 32]).unwrap()),
        addr_of(&SigningKey::from_slice(&[0x32; 32]).unwrap()),
    ];

    // The HONEST gateway: seed a NON-EMPTY genesis (verified human + funded account + jurors + CSCA +
    // governance) and seal the anchor BEFORE producing any block — exactly what the node does at boot.
    let chain = Chain::new(chain_id, genesis_time).with_proposer_key(proposer);
    seed_genesis(&chain, dev, &jurors, genesis_time);
    chain.seal_genesis();
    let anchor = chain.genesis_anchor().unwrap();

    // The client imports the seeded genesis with the pinned root + pinned validator set. It STARTS from
    // the seeded state — NOT empty — so block #1's state_root (which reflects the seeded accounts) is
    // reproducible (this is the `ln-trust-2` non-functional-product fix).
    let mut light = import_from_anchor(&chain, vec![proposer_addr]);
    assert_eq!(
        light.state_root(),
        anchor.state_root.0,
        "the imported verified state must re-derive to the pinned seeded genesis root"
    );
    // The seeded dev account's streaming balance is already visible at genesis (emission since genesis).
    let dev_bal_genesis = light.balance_of(&dev, genesis_time);
    assert!(
        dev_bal_genesis >= 1_000 * UBI,
        "the seeded dev account must carry its genesis balance in the verified state"
    );

    // Produce a corpus of REAL blocks on top of the seeded genesis (block #1 onward) and re-execute each
    // in the client; the client's state_root must match the honest gateway's at EVERY height. Capture the
    // committed per-account balances RIGHT AFTER producing each block (the per-height read, not the
    // final-tip read — reading after all blocks would read the FINAL state).
    let mut blocks: Vec<(Block, u64, Vec<u128>)> = Vec::new();

    // Block #1: dev → bob transfer (only possible because the seeded dev account has a balance).
    let t1 = genesis_time + 100;
    chain
        .ingest_gossip_tx(&signed_tx(&dev_sk, chain_id, bob, 10 * UBI, vec![], 0))
        .expect("dev→bob transfer admitted");
    let b1 = chain.produce_block(t1);
    blocks.push((
        b1,
        t1,
        vec![chain.balance(&dev, t1), chain.balance(&bob, t1)],
    ));

    // Block #2: bob → dev (bob is now funded), exercising a second account derived from the seeded one.
    let t2 = genesis_time + 200;
    chain
        .ingest_gossip_tx(&signed_tx(&bob_sk, chain_id, dev, UBI, vec![], 0))
        .expect("bob→dev transfer admitted");
    let b2 = chain.produce_block(t2);
    blocks.push((
        b2,
        t2,
        vec![chain.balance(&dev, t2), chain.balance(&bob, t2)],
    ));

    // Block #3: an empty tick (still advances height + emission).
    let t3 = genesis_time + 300;
    let b3 = chain.produce_block(t3);
    blocks.push((
        b3,
        t3,
        vec![chain.balance(&dev, t3), chain.balance(&bob, t3)],
    ));

    for (b, now, want) in &blocks {
        let wire = wire_block_for(&chain, b);
        let outcome = light
            .apply_decoded(&wire, Some(proposer_addr))
            .unwrap_or_else(|e| {
                panic!(
                    "client must re-execute seeded-chain block {}: {e}",
                    b.number
                )
            });
        // Byte-identical state_root vs the honest gateway at this height.
        assert_eq!(
            outcome.state_root, b.state_root.0,
            "state_root diverged at seeded block {}",
            b.number
        );
        assert_eq!(
            light.state_root(),
            chain.state_root_at(b.number).unwrap().0,
            "client vs gateway state_root diverged at seeded block {}",
            b.number
        );
        // balanceOf parity for the seeded + derived accounts at this height.
        for (i, who) in [dev, bob].iter().enumerate() {
            assert_eq!(
                light.balance_of(who, *now).to_string(),
                want[i].to_string(),
                "balanceOf diverged for {who:?} at seeded block {}",
                b.number
            );
        }
    }

    // The seeded dev human is Verified on the client too (the seeded human registry round-tripped).
    assert_eq!(
        light.human_status(&dev),
        2,
        "the seeded dev account must be a Verified human in the imported state"
    );
}

/// The EVM address of a 32-byte proposer secret (matching `ProposerKey::from_bytes(...).address()`).
fn proposer_addr_of(secret: &[u8; 32]) -> [u8; 20] {
    ProposerKey::from_bytes(secret)
        .unwrap()
        .address()
        .into_array()
}

/// Re-propose a block under a different proposer secret: stamp the secret's EVM address as `proposer`,
/// recompute the header hash, and sign it (65-byte `r‖s‖v`, the encoding `recover_proposer` expects). The
/// `state_root`/`txs` are unchanged (re-execution is proposer-independent — the kernel's entropy hash
/// zeroes the proposer), so the re-proposed block is self-consistent + shallow-verifies, yet its proposer
/// is the attacker's. This models a malicious gateway signing a self-consistent chain with its own key.
fn repropose_under(wire: &WasmWireBlock, secret: &[u8; 32]) -> WasmWireBlock {
    let sk = SigningKey::from_slice(secret).unwrap();
    let attacker = addr_of(&sk);
    let mut b = wire.clone();
    b.proposer = AlloyAddr::from(attacker);
    // Sign the NEW header hash (the proposer is in the pre-image, so the hash changed).
    let hash = b.hash();
    let (sig, recid) = sk.sign_prehash_recoverable(hash.as_slice()).unwrap();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&sig.r().to_bytes());
    out.extend_from_slice(&sig.s().to_bytes());
    out.push(27 + recid.to_byte());
    b.proposer_sig = out;
    b
}
