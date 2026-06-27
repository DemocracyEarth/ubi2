//! GATE 3 — Security PoCs for M5 Stage A (P2P networking + block sync).
//!
//! Defender-side proofs that the consensus/networking surface fails closed under a hostile peer. These
//! are LIVE assertions against the real `Chain::validate_and_apply_block` follower path and the real
//! `ubi2_network::wire` decoders — no mocks of the code under test. Grouped by the threat-model items:
//!
//!   (1) BLOCK FORGERY: forged/absent proposer signature, wrong proposer, future/skipped number, wrong
//!       parent, tampered txs — each rejected with NO state change (fail-closed).
//!   (2) SYNC bounds: an over-large `Blocks` count is rejected at decode; a forged-huge tx count in a
//!       block does not pre-allocate or panic.
//!   (4) MALFORMED MESSAGES: hostile/garbage bytes to every wire decoder reject cleanly (never panic).
//!   (5) HANDSHAKE: the PeerId<->validator binding cannot be forged by replaying another node's proof.
//!
//! Run: `cargo test -p ubi2-rpc --test sec_m5a`.

use std::sync::Arc;

use alloy_consensus::{SignableTransaction, TxEnvelope, TxLegacy};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{
    address, keccak256, Address as AlloyAddr, PrimitiveSignature, TxKind, B256, U256,
};
use k256::ecdsa::SigningKey;

use ubi2_network::consts::{
    MAX_BLOCK_BYTES, MAX_TX_BYTES, MEMPOOL_MAX_PER_SENDER, MEMPOOL_MAX_TXS, SYNC_MAX_BATCH,
};
use ubi2_network::wire::{
    Blocks, GetBlocks, Hello, SyncRequest, SyncResponse, TxAnnounce, WireBlock, WireError,
};
use ubi2_rpc::{BlockError, Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::Account;

const DEV_PRIVKEY: [u8; 32] =
    hex32("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const DEV_ADDR: AlloyAddr = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
const PAYEE: AlloyAddr = address!("70997970C51812dc3A010C7d01b50e0d17dc79C8");
/// The designated proposer's PUBLIC devnet key (Anvil acct #2).
const PROPOSER_KEY: [u8; 32] =
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
/// An ATTACKER key that is NOT the designated proposer (Anvil acct #3).
const ATTACKER_KEY: [u8; 32] =
    hex32("7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6");

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

fn addr_of(key: &[u8; 32]) -> AlloyAddr {
    let sk = SigningKey::from_slice(key).unwrap();
    let p = sk.verifying_key().to_encoded_point(false);
    let h = keccak256(&p.as_bytes()[1..]);
    AlloyAddr::from_slice(&h[12..])
}

fn sign_digest(key: &[u8; 32], digest: &B256) -> Vec<u8> {
    let sk = SigningKey::from_slice(key).unwrap();
    let (sig, recid) = sk.sign_prehash_recoverable(digest.as_slice()).unwrap();
    let mut out = Vec::with_capacity(65);
    out.extend_from_slice(&sig.r().to_bytes());
    out.extend_from_slice(&sig.s().to_bytes());
    out.push(27 + recid.to_byte());
    out
}

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

/// Produce a real, validly-signed block #1 (one transfer) on a proposer chain, plus its user raw txs.
fn good_block_and_raw(proposer: &Chain) -> (ubi2_rpc::Block, Vec<Vec<u8>>) {
    let t = 1_000 + 7 * 3600;
    let raw0 = sign_transfer(&DEV_PRIVKEY, PAYEE, 1_000_000, 0);
    proposer.ingest_gossip_tx(&raw0).expect("admit tx0");
    let block = proposer.produce_block(t);
    (block, vec![raw0])
}

// =============================================================================================
// (1) BLOCK FORGERY — every hostile block is rejected with NO state change (fail-closed).
// =============================================================================================

/// FORGE-1: absent signature. A networked follower (`expected_proposer = Some`) must reject a block
/// whose `proposer_sig` is empty — an unsigned block is only valid in the single-node devnet.
#[test]
fn forge_absent_signature_rejected() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let (block, raw) = good_block_and_raw(&proposer);

    let follower = genesis_chain(None);
    let before = follower.state_root();
    let err = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &[], // STRIP the signature
            &raw,
            Some(pkey.address()),
        )
        .unwrap_err();
    assert_eq!(err, BlockError::BadSignature, "absent sig must be rejected");
    assert_eq!(follower.tip().0, 0, "no block applied");
    assert_eq!(
        follower.state_root(),
        before,
        "state unchanged (fail-closed)"
    );
}

/// FORGE-2: forged signature by a non-proposer. The attacker signs the *correct* header hash with its
/// OWN key and stamps the legitimate proposer address — `ecrecover` recovers the attacker, not the
/// claimed proposer, so the signature does not match the author ⇒ rejected.
#[test]
fn forge_signature_by_non_proposer_rejected() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let (block, raw) = good_block_and_raw(&proposer);

    // Attacker signs the genuine header hash but with its own (non-proposer) key.
    let forged_sig = sign_digest(&ATTACKER_KEY, &block.hash);
    assert_ne!(addr_of(&ATTACKER_KEY), pkey.address());

    let follower = genesis_chain(None);
    let err = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer, // still claims the legitimate proposer
            &forged_sig,
            &raw,
            Some(pkey.address()),
        )
        .unwrap_err();
    assert_eq!(
        err,
        BlockError::BadSignature,
        "sig must recover to the claimed proposer"
    );
    assert_eq!(follower.tip().0, 0);
}

/// FORGE-3: attacker is the author. The attacker produces a fully self-consistent block (its own
/// address as proposer, signed by its own key, correct roots) — but it is not the DESIGNATED proposer,
/// so the author check rejects it before any state mutation (AC-F3).
#[test]
fn forge_self_consistent_wrong_author_rejected() {
    // Attacker runs its own proposer chain and produces a perfectly valid block under ITS key.
    let akey = Arc::new(ProposerKey::from_bytes(&ATTACKER_KEY).unwrap());
    let attacker = genesis_chain(Some(akey.clone()));
    let (block, raw) = good_block_and_raw(&attacker);
    assert_eq!(block.proposer, akey.address());

    // The honest follower expects the DESIGNATED proposer (acct #2), not the attacker (acct #3).
    let designated = addr_of(&PROPOSER_KEY);
    let follower = genesis_chain(None);
    let err = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &raw,
            Some(designated),
        )
        .unwrap_err();
    assert_eq!(
        err,
        BlockError::WrongProposer,
        "only the designated proposer may author"
    );
    assert_eq!(follower.tip().0, 0);
}

/// FORGE-4: skipped / future block number. A block at height head+2 (or any non-contiguous height) is
/// rejected as NonContiguous (it must be exactly head+1) — the follower never jumps ahead on gossip.
#[test]
fn forge_skipped_number_rejected() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let (block, raw) = good_block_and_raw(&proposer);

    let follower = genesis_chain(None);
    // Claim height 5 (head is 0). Even with a present-but-wrong signature the height check fails first.
    let err = follower
        .validate_and_apply_block(
            5,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &raw,
            Some(pkey.address()),
        )
        .unwrap_err();
    assert!(matches!(err, BlockError::NonContiguous { have: 0, got: 5 }));
    assert_eq!(follower.tip().0, 0);
}

/// FORGE-5: tampered tx set. The block header's `txs_root` is genuine, but the attacker swaps in a
/// DIFFERENT raw tx. Re-execution produces a different `txs_root`/`state_root`/`hash` than the signed
/// header ⇒ rejected and rolled back. (Also: `WireBlock::shallow_verify` independently catches this at
/// the network layer before the block is ever surfaced to the node.)
#[test]
fn forge_tampered_txs_rejected_and_rolled_back() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let (block, _raw) = good_block_and_raw(&proposer);

    // Attacker substitutes a different (still validly-signed) tx for the committed one.
    let evil_raw = sign_transfer(&DEV_PRIVKEY, PAYEE, 9_999_999, 0);

    let follower = genesis_chain(None);
    let before = follower.state_root();
    let err = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root, // the genuine root (commits the ORIGINAL tx)
            block.state_root,
            block.proposer,
            &block.proposer_sig,             // signs the genuine header
            std::slice::from_ref(&evil_raw), // but the carried tx is different
            Some(pkey.address()),
        )
        .unwrap_err();
    assert!(
        matches!(err, BlockError::StateRootMismatch { .. }),
        "tampered tx set must mismatch the committed roots"
    );
    assert_eq!(follower.tip().0, 0, "no block applied");
    assert_eq!(follower.state_root(), before, "rolled back to a no-op");

    // And the network layer's shallow_verify rejects it too: build the wire block with the swapped tx.
    let wb = WireBlock {
        number: block.number,
        parent_hash: block.parent_hash,
        timestamp: block.timestamp,
        txs_root: block.txs_root,
        state_root: block.state_root,
        proposer: block.proposer,
        proposer_sig: block.proposer_sig.clone(),
        txs: vec![evil_raw],
    };
    assert!(
        !wb.shallow_verify(),
        "shallow_verify catches a txs_root mismatch"
    );
}

/// FORGE-6: competing chain (wrong parent at the right height). A block at the right height but built on
/// a different parent hash is rejected (WrongParent) — a peer cannot splice a fork onto our head.
#[test]
fn forge_competing_chain_wrong_parent_rejected() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let (block, raw) = good_block_and_raw(&proposer);

    let follower = genesis_chain(None);
    let err = follower
        .validate_and_apply_block(
            block.number,
            B256::repeat_byte(0xde), // a parent that is not our genesis
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &raw,
            Some(pkey.address()),
        )
        .unwrap_err();
    assert_eq!(err, BlockError::WrongParent);
    assert_eq!(follower.tip().0, 0);
}

/// FORGE-7: a genuine block from the designated proposer DOES apply (the positive control — proves the
/// rejections above are specific, not a blanket deny).
#[test]
fn good_block_applies_positive_control() {
    let pkey = Arc::new(ProposerKey::from_bytes(&PROPOSER_KEY).unwrap());
    let proposer = genesis_chain(Some(pkey.clone()));
    let (block, raw) = good_block_and_raw(&proposer);

    let follower = genesis_chain(None);
    let applied = follower
        .validate_and_apply_block(
            block.number,
            block.parent_hash,
            block.timestamp,
            block.txs_root,
            block.state_root,
            block.proposer,
            &block.proposer_sig,
            &raw,
            Some(pkey.address()),
        )
        .expect("the genuine block must apply");
    assert_eq!(applied.state_root, block.state_root);
    assert_eq!(follower.tip(), proposer.tip());
}

// =============================================================================================
// (2) SYNC bounds + (4) MALFORMED messages — decoders reject cleanly, never panic / never over-alloc.
// =============================================================================================

/// SYNC-1: a `Blocks` response claiming more than `SYNC_MAX_BATCH` blocks is rejected at decode — the
/// joiner never pre-allocates an unbounded vector from an attacker-chosen count.
#[test]
fn sync_oversize_block_count_rejected() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&((SYNC_MAX_BATCH + 1) as u32).to_be_bytes());
    assert_eq!(Blocks::decode(&buf), Err(WireError::TooLong));

    // A u32::MAX count must also reject immediately (no 4-billion-element allocation attempt).
    let mut huge = Vec::new();
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(Blocks::decode(&huge), Err(WireError::TooLong));
}

/// SYNC-2: a single block claiming a forged-huge tx count does not pre-allocate gigabytes or panic — the
/// count is bounded before the read loop, and the buffer is too short, so it errors cleanly.
#[test]
fn block_forged_huge_tx_count_does_not_alloc_or_panic() {
    // Encode a header then a tx count of u32::MAX with no tx bytes following.
    let mut buf = Vec::new();
    buf.extend_from_slice(&1u64.to_be_bytes()); // number
    buf.extend_from_slice(B256::ZERO.as_slice()); // parent
    buf.extend_from_slice(&1u64.to_be_bytes()); // timestamp
    buf.extend_from_slice(B256::ZERO.as_slice()); // txs_root
    buf.extend_from_slice(B256::ZERO.as_slice()); // state_root
    buf.extend_from_slice(AlloyAddr::ZERO.as_slice()); // proposer
    buf.extend_from_slice(&0u32.to_be_bytes()); // proposer_sig len = 0
    buf.extend_from_slice(&u32::MAX.to_be_bytes()); // tx count = 4 billion
    let err = WireBlock::decode(&buf).unwrap_err();
    assert!(
        matches!(err, WireError::TooLong | WireError::Truncated),
        "huge tx count must reject without allocating, got {err:?}"
    );
}

/// MALF-1: random/garbage bytes to EVERY wire decoder must return an error, never panic. We fuzz a set
/// of adversarial buffers (empty, 1 byte, truncated-after-each-field-boundary, oversized) across the tx,
/// block, hello, and sync decoders.
#[test]
fn malformed_bytes_never_panic_any_decoder() {
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff; 3],
        vec![0xff; 33],
        vec![0x01; 64],
        vec![0xAB; 200],
    ];
    // Deterministic pseudo-random buffers of varied lengths.
    let mut seed = 0x1234_5678u32;
    for len in [5usize, 16, 31, 47, 65, 100, 257, 1024] {
        let mut v = Vec::with_capacity(len);
        for _ in 0..len {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            v.push((seed >> 16) as u8);
        }
        cases.push(v);
    }

    for buf in &cases {
        // None of these may panic; an Err is the only acceptable failure mode for garbage.
        let _ = TxAnnounce::decode(buf);
        let _ = WireBlock::decode(buf);
        let _ = Hello::decode(buf);
        let _ = GetBlocks::decode(buf);
        let _ = Blocks::decode(buf);
        let _ = SyncRequest::decode(buf);
        let _ = SyncResponse::decode(buf);
    }
}

/// MALF-2: an over-size tx / block payload is rejected by the size bound before any hashing/parsing.
#[test]
fn oversize_payloads_rejected_by_bound() {
    assert_eq!(
        TxAnnounce::decode(&vec![0u8; MAX_TX_BYTES + 1]),
        Err(WireError::TooLong)
    );
    assert_eq!(
        WireBlock::decode(&vec![0u8; MAX_BLOCK_BYTES + 1]),
        Err(WireError::TooLong)
    );
}

/// MALF-3: trailing bytes after a canonical message are rejected (non-canonical ⇒ the message-id /
/// dedup contract would be ambiguous). Proves the decoders enforce exactly-one-encoding.
#[test]
fn trailing_bytes_rejected() {
    let get = GetBlocks { from: 1, to: 9 };
    let mut enc = get.encode();
    enc.push(0x00);
    assert_eq!(GetBlocks::decode(&enc), Err(WireError::TrailingBytes));
}

// =============================================================================================
// (5) HANDSHAKE — the PeerId<->validator binding cannot be forged / replayed across peers.
// =============================================================================================

/// HS-1: a stolen `peer_proof` does not let a different PeerId impersonate a validator. The proof binds
/// `keccak256(peer_id_bytes || genesis_hash)`; verifying it under a DIFFERENT peer_id yields `None`.
#[test]
fn handshake_binding_not_replayable_across_peers() {
    let validator = addr_of(&PROPOSER_KEY);
    let genesis = B256::repeat_byte(0xab);
    let victim_peer = b"victim-peer-id-bytes";
    let proof = sign_digest(&PROPOSER_KEY, &Hello::proof_digest(victim_peer, &genesis));

    let hello = Hello {
        genesis_hash: genesis,
        chain_id: DEVNET_CHAIN_ID,
        tip: (10, B256::repeat_byte(0xcd)),
        validator: Some(validator),
        peer_proof: proof,
        protocol_ver: ubi2_network::consts::PROTOCOL_VERSION,
    };
    // Under the victim's PeerId the binding verifies...
    assert_eq!(hello.verify_binding(victim_peer), Some(validator));
    // ...but an attacker replaying the same Hello from a DIFFERENT PeerId binds to nothing.
    assert_eq!(hello.verify_binding(b"attacker-peer-id-bytes"), None);
    // A claimed validator with NO proof also binds to nothing (cannot self-assert a validator address).
    let unproven = Hello {
        peer_proof: vec![],
        ..hello.clone()
    };
    assert_eq!(unproven.verify_binding(victim_peer), None);
}

// =============================================================================================
// (2/3) SYNC-LOOP DoS — FIXED (SEC-M5A-1). A forged high block number no longer passes the
// network-layer shallow_verify gate, so it never reaches `on_block` to pin a bogus tip.
//
// Previously: `on_block` (crates/node/src/net.rs) treated a gossiped block whose `number > head + 1` as
// "we're behind", recorded the peer's tip = the *block's claimed number*, and drove sync. The only gate
// before `on_block` was `WireBlock::shallow_verify`, which SKIPPED the proposer-sig check when the
// signature was empty — so an UNSIGNED block with empty txs and a claimed number of u64::MAX passed and
// pinned a follower's view of the peer's tip to u64::MAX, and `on_sync_response` re-issued the range pull
// on every (incl. empty/timeout) response, looping indefinitely without penalizing the peer.
//
// Now: `shallow_verify` FAILS CLOSED on an absent signature; `on_block` additionally requires an
// ahead-block to be signed by the DESIGNATED proposer before pinning its tip; `maybe_sync` refuses a tip
// beyond SYNC_MAX_LOOKAHEAD; and `on_sync_response` only re-requests on forward progress, penalizing +
// abandoning a peer after SYNC_MAX_NO_PROGRESS_ROUNDS of no progress. The regression assertion below
// pins the first link of that chain.
// =============================================================================================

/// SYNCLOOP-1 (regression, SEC-M5A-1 FIXED): a forged UNSIGNED block claiming `number = u64::MAX` with
/// empty txs must NOW FAIL the network layer's `shallow_verify`, so it never reaches `on_block` and can
/// never pin a peer's tip to u64::MAX. The previous version of this test asserted the *vulnerability*
/// (that it passed); the fix inverts the expectation.
#[test]
fn syncloop_forged_high_number_fails_shallow_verify() {
    let mut forged = WireBlock {
        number: u64::MAX, // absurd height: "I am billions of blocks ahead"
        parent_hash: B256::repeat_byte(0x77),
        timestamp: 9_999_999_999,
        txs_root: B256::ZERO,
        state_root: B256::repeat_byte(0x88),
        proposer: AlloyAddr::ZERO,
        proposer_sig: vec![], // UNSIGNED ⇒ FAIL CLOSED (was: shallow_verify skipped the sig check)
        txs: vec![],          // empty ⇒ txs_root is trivially satisfiable
    };
    forged.txs_root = forged.recompute_txs_root();
    assert!(
        !forged.shallow_verify(),
        "SEC-M5A-1: an unsigned, empty, absurd-height block must now FAIL shallow_verify — it can no \
         longer reach on_block to pin a peer's tip = u64::MAX and drive an unbounded sync loop"
    );
    // It still round-trips on the wire (it is a structurally valid announcement an attacker can craft) —
    // the defense is the validity gate, not the decoder. The point is the gate now rejects it.
    let enc = forged.encode();
    assert_eq!(WireBlock::decode(&enc).unwrap(), forged);

    // A block SIGNED by the designated proposer over its real header DOES pass — the gate is selective,
    // not a blanket block on high numbers (a genuinely-far-ahead proposer can still announce).
    let mut signed = WireBlock {
        number: 1_000,
        parent_hash: B256::repeat_byte(0x12),
        timestamp: 1_700_000_000,
        txs_root: B256::ZERO,
        state_root: B256::repeat_byte(0x34),
        proposer: addr_of(&PROPOSER_KEY),
        proposer_sig: vec![],
        txs: vec![],
    };
    signed.txs_root = signed.recompute_txs_root();
    signed.proposer_sig = sign_digest(&PROPOSER_KEY, &signed.hash());
    assert!(
        signed.shallow_verify(),
        "a properly-signed proposer block must still shallow-verify"
    );
}

/// SYNCLOOP-2: the sync server's range read is bounded to SYNC_MAX_BATCH (so each individual response is
/// capped). SEC-M5A-2 additionally rate-limits the inbound sync request-response path and caps concurrent
/// in-flight pulls per peer (see `crates/network/src/ratelimit.rs` tests); the per-request size cap is
/// proven here at the wire layer.
#[test]
fn syncloop_response_is_batch_bounded() {
    // The wire-level batch cap is enforced: a response can never carry more than SYNC_MAX_BATCH blocks.
    let mut over = Vec::new();
    over.extend_from_slice(&((SYNC_MAX_BATCH + 1) as u32).to_be_bytes());
    assert_eq!(Blocks::decode(&over), Err(WireError::TooLong));
    // A GetBlocks request carrying an enormous range still decodes (it is the SERVER that clamps `to` to
    // from + SYNC_MAX_BATCH - 1 in on_sync_request) — so the request itself is cheap to craft and flood.
    let huge = GetBlocks {
        from: 0,
        to: u64::MAX,
    };
    assert_eq!(GetBlocks::decode(&huge.encode()).unwrap(), huge);
}

/// HS-2: a proof bound to a DIFFERENT genesis (wrong network) does not verify against our genesis — the
/// binding domain-separates by genesis hash, so a cross-network proof is rejected.
#[test]
fn handshake_binding_domain_separated_by_genesis() {
    let validator = addr_of(&PROPOSER_KEY);
    let peer = b"peer-id-bytes";
    let other_genesis = B256::repeat_byte(0x01);
    let our_genesis = B256::repeat_byte(0x02);
    let proof = sign_digest(&PROPOSER_KEY, &Hello::proof_digest(peer, &other_genesis));
    let hello = Hello {
        genesis_hash: our_genesis, // claims our genesis, but the proof was over a different one
        chain_id: DEVNET_CHAIN_ID,
        tip: (0, our_genesis),
        validator: Some(validator),
        peer_proof: proof,
        protocol_ver: ubi2_network::consts::PROTOCOL_VERSION,
    };
    assert_eq!(
        hello.verify_binding(peer),
        None,
        "cross-genesis proof must not bind"
    );
}

// =============================================================================================
// (3/3) MEMPOOL DoS — SEC-M5A-3. `ingest_raw_tx` enforces BOTH the global cap (MEMPOOL_MAX_TXS) and
// the per-sender cap (MEMPOOL_MAX_PER_SENDER) at admission; over-cap txs are rejected with a clear
// JSON-RPC error instead of growing the mempool unboundedly.
// =============================================================================================

/// Seed a verified account with a very large settled balance so it can afford many txs (the cap, not
/// the balance, is what we are testing). `key` is its private key.
fn seed_funded(chain: &Chain, key: &[u8; 32], genesis_time: u64) -> AlloyAddr {
    let addr = addr_of(key);
    chain.seed_account(Account {
        address: addr.into_array(),
        verified: true,
        verified_at: genesis_time,
        last_settled_at: genesis_time,
        settled_balance: u128::MAX / 2, // plenty to fund thousands of small transfers
        nonce: 0,
    });
    chain.seed_verified_human(&addr.into_array(), genesis_time);
    addr
}

/// MEMPOOL-1 (SEC-M5A-3): a single sender cannot exceed `MEMPOOL_MAX_PER_SENDER` pending txs. The first
/// `MEMPOOL_MAX_PER_SENDER` admit; the next is rejected with a "per-sender cap" error — and the mempool
/// does not grow past the cap for that sender.
#[test]
fn mempool_enforces_per_sender_cap() {
    let genesis_time = 1_000u64;
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis_time);
    // A funded key distinct from DEV (any 32 bytes that form a valid secp256k1 scalar).
    let key = [0x11u8; 32];
    seed_funded(&chain, &key, genesis_time);

    for nonce in 0..MEMPOOL_MAX_PER_SENDER as u64 {
        let raw = sign_transfer(&key, PAYEE, 1, nonce);
        chain
            .ingest_gossip_tx(&raw)
            .unwrap_or_else(|e| panic!("tx {nonce} within the per-sender cap must admit: {e}"));
    }
    // The (cap+1)-th tx from the SAME sender is rejected at the per-sender cap.
    let over = sign_transfer(&key, PAYEE, 1, MEMPOOL_MAX_PER_SENDER as u64);
    let err = chain
        .ingest_gossip_tx(&over)
        .expect_err("a tx over the per-sender cap must be rejected");
    assert!(
        err.contains("per-sender cap"),
        "rejection must name the per-sender cap; got: {err}"
    );
}

/// MEMPOOL-2 (SEC-M5A-3): the GLOBAL cap bounds the total mempool across all senders. Filling it with
/// many distinct senders (each under the per-sender cap) up to `MEMPOOL_MAX_TXS`, the next tx — from a
/// fresh sender with a clean per-sender budget — is still rejected at the global cap.
#[test]
fn mempool_enforces_global_cap() {
    let genesis_time = 1_000u64;
    let chain = Chain::new(DEVNET_CHAIN_ID, genesis_time);

    // Distinct senders, each contributing `per_sender` txs, until the global cap is full. We need
    // ceil(MEMPOOL_MAX_TXS / per_sender) senders; derive each key deterministically from an index.
    let per_sender = MEMPOOL_MAX_PER_SENDER;
    let mut admitted = 0usize;
    let mut sender_idx = 0u32;
    while admitted < MEMPOOL_MAX_TXS {
        // A deterministic, valid secp256k1 key from the sender index (avoid the all-zero scalar).
        let mut key = [0u8; 32];
        key[28..].copy_from_slice(&(sender_idx + 1).to_be_bytes());
        seed_funded(&chain, &key, genesis_time);
        for nonce in 0..per_sender as u64 {
            if admitted >= MEMPOOL_MAX_TXS {
                break;
            }
            let raw = sign_transfer(&key, PAYEE, 1, nonce);
            chain
                .ingest_gossip_tx(&raw)
                .expect("tx within both caps must admit");
            admitted += 1;
        }
        sender_idx += 1;
    }
    assert_eq!(
        admitted, MEMPOOL_MAX_TXS,
        "mempool filled to exactly the global cap"
    );

    // A fresh sender (clean per-sender budget) is now rejected at the GLOBAL cap.
    let mut fresh = [0u8; 32];
    fresh[27] = 0xAB;
    fresh[31] = 0xCD;
    seed_funded(&chain, &fresh, genesis_time);
    let over = sign_transfer(&fresh, PAYEE, 1, 0);
    let err = chain
        .ingest_gossip_tx(&over)
        .expect_err("a tx over the global cap must be rejected even for a fresh sender");
    assert!(
        err.contains("global cap"),
        "rejection must name the global cap; got: {err}"
    );
}
