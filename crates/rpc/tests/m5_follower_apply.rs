//! M5 Stage A — A4 follower block validation (`Chain::validate_and_apply_block`).
//!
//! Proves the I1/I2 cross-node invariant at the unit level: a proposer produces a signed block; an
//! independent follower (a fresh chain seeded with the SAME genesis) re-executes the block's committed
//! tx order and reaches a **byte-identical `state_root`** — the EC-4/EC-10 bar. Plus the fail-closed
//! rejections (AC-F2/AC-F3): a tampered `state_root`, a wrong proposer, and a wrong parent are all
//! rejected and apply NO state change.

use std::sync::Arc;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{address, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256};
use k256::ecdsa::SigningKey;

use ubi2_rpc::{BlockError, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::Account;

const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const PAYEE: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");

/// The proposer's PUBLIC devnet validator key (Anvil acct #2) — distinct from the dev tx signer.
const PROPOSER_KEY: [u8; 32] =
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[i * 2]) << 4) | nib(b[i * 2 + 1]);
        i += 1;
    }
    out
}
const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Sign an EIP-155 transfer to `to` of `value` base units at `nonce`, returning 2718 raw bytes.
fn sign_transfer(key: &[u8; 32], to: AlloyAddr, value: u128, nonce: u64) -> Vec<u8> {
    let tx = TxLegacy {
        chain_id: Some(DEVNET_CHAIN_ID),
        nonce,
        gas_price: 1_000_000_000,
        gas_limit: 300_000,
        to: TxKind::Call(to),
        value: U256::from(value),
        input: Vec::new().into(),
    };
    let sk = SigningKey::from_slice(key).unwrap();
    let sighash = tx.signature_hash();
    let (sig, recid) = sk.sign_prehash_recoverable(sighash.as_slice()).unwrap();
    let r: [u8; 32] = sig.r().to_bytes().into();
    let s: [u8; 32] = sig.s().to_bytes().into();
    let alloy_sig =
        PrimitiveSignature::from_scalars_and_parity(r.into(), s.into(), recid.is_y_odd());
    let env: TxEnvelope = tx.into_signed(alloy_sig).into();
    let mut raw = Vec::new();
    env.encode_2718(&mut raw);
    raw
}

/// A fresh chain seeded with the exact genesis the devnet node seeds (the dev account, Verified at
/// genesis), at a FIXED `genesis_time` so every node's genesis hash matches.
fn genesis_chain(proposer: Option<Arc<ProposerKey>>) -> Chain {
    let genesis_time = 1_000u64;
    let mut chain = Chain::new(DEVNET_CHAIN_ID, genesis_time);
    if let Some(k) = proposer {
        chain = chain.with_proposer_key(k);
    }
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: 0,
        nonce: 0,
    });
    chain.seed_verified_human(&DEV_ADDR.into_array(), genesis_time);
    chain
}

/// The raw user-tx bytes the proposer included, recovered from a separate, known list (the node keeps a
/// hash→raw cache; here the test simply knows the bytes it submitted, in block order).
fn block_user_raw(raws: &[Vec<u8>]) -> Vec<Vec<u8>> {
    raws.to_vec()
}

#[test]
fn follower_reaches_identical_state_root() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));

    // Two transfers from the dev account at a future timestamp (so emission has accrued enough to fund).
    let t = 1_000 + 7 * 3600; // 7 hours of emission ⇒ ~7 UBI, plenty for two small transfers + fee
    let raw0 = sign_transfer(&DEV_PRIVKEY, PAYEE, 1_000_000, 0);
    let raw1 = sign_transfer(&DEV_PRIVKEY, PAYEE, 2_000_000, 1);
    proposer.ingest_gossip_tx(&raw0).expect("admit tx0");
    proposer.ingest_gossip_tx(&raw1).expect("admit tx1");

    let block = proposer.produce_block(t);
    assert_eq!(block.number, 1);
    assert_eq!(block.proposer, pkey.address());
    // Two user txs were included (no sweep here — no PoH lifecycle in this block).
    assert!(block.txs.len() >= 2);

    let user_raw = block_user_raw(&[raw0.clone(), raw1.clone()]);

    // A fresh, independent follower with the same genesis re-executes the committed order.
    let follower = genesis_chain(None);
    assert_eq!(
        follower.genesis_hash(),
        proposer.genesis_hash(),
        "same genesis_time ⇒ identical genesis hash (network-identity anchor)"
    );

    let applied = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &user_raw,
            Some(pkey.address()),
        )
        .expect("follower applies the proposer's block");

    // The I1/I2 bar: byte-identical state root + identical committed block hash.
    assert_eq!(
        applied.state_root, block.state_root,
        "EC-4/EC-10 state_root"
    );
    assert_eq!(applied.hash, block.hash, "identical header hash");
    assert_eq!(follower.state_root(), proposer.state_root());
    assert_eq!(follower.tip(), proposer.tip());
    // And balances agree at the same height (I2).
    assert_eq!(
        follower.balance(&PAYEE.into_array(), t),
        proposer.balance(&PAYEE.into_array(), t)
    );
}

#[test]
fn follower_rejects_tampered_state_root_no_apply() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let t = 1_000 + 7 * 3600;
    let raw0 = sign_transfer(&DEV_PRIVKEY, PAYEE, 1_000_000, 0);
    proposer.ingest_gossip_tx(&raw0).unwrap();
    let block = proposer.produce_block(t);

    let follower = genesis_chain(None);
    let before = follower.state_root();
    let bad_root = B256::repeat_byte(0xEE);
    let err = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            bad_root, // claim a state root the re-execution will not produce
            block.proposer,
            &block.proposer_sig,
            std::slice::from_ref(&raw0),
            Some(pkey.address()),
        )
        .unwrap_err();
    assert!(
        matches!(err, BlockError::StateRootMismatch { .. })
            || matches!(err, BlockError::BadSignature)
    );
    // Fail-closed: nothing was applied (tip + root unchanged).
    assert_eq!(follower.tip().0, 0, "no block applied");
    assert_eq!(
        follower.state_root(),
        before,
        "state rolled back to a no-op"
    );
}

#[test]
fn follower_rejects_wrong_proposer() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let t = 1_000 + 7 * 3600;
    let block = proposer.produce_block(t); // empty block, validly signed by pkey

    let follower = genesis_chain(None);
    // Designate a DIFFERENT expected proposer ⇒ the block's author is not authorized (AC-F3).
    let other = AlloyAddr::repeat_byte(0x99);
    let err = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &[],
            Some(other),
        )
        .unwrap_err();
    assert_eq!(err, BlockError::WrongProposer);
    assert_eq!(follower.tip().0, 0);
}

#[test]
fn follower_rejects_wrong_parent() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let block = proposer.produce_block(1_000 + 7 * 3600);

    let follower = genesis_chain(None);
    let err = follower
        .validate_and_apply_block(
            block.number,
            B256::repeat_byte(0x01), // not the follower's genesis hash
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &[],
            Some(pkey.address()),
        )
        .unwrap_err();
    assert_eq!(err, BlockError::WrongParent);
    assert_eq!(follower.tip().0, 0);
}
