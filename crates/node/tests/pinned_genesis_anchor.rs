//! Regression guard for the SHIPPED light-client pinned genesis anchor (spec 07 §3.4, `ln-trust-1/2/3`).
//!
//! The browser app (`apps/light-node/src/config.ts`) carries HARD-CODED genesis anchor constants — the
//! genesis hash, the seeded genesis `state_root`, and the authorized PoA proposer — derived from the
//! canonical devnet genesis (`genesis_time = 1700000000`). If the genesis seeding ever changes (a new
//! seeded account, a different CSCA, a changed juror set, a `state_root` format bump, …) those pinned
//! constants would silently go stale and the shipped app would reject EVERY honest gateway (or, worse,
//! fail to catch a lying one). This test recomputes the canonical anchor from the SAME seeds `main.rs`
//! applies and asserts it equals the pinned constants — so such a drift fails CI with a clear pointer to
//! re-pin `config.ts`.
//!
//! KEEP IN SYNC with both `crates/node/src/main.rs` (the genesis seeds) and
//! `apps/light-node/src/config.ts` (the pinned constants).

use std::sync::Arc;

use alloy_primitives::address;
use ubi2_rpc::{Chain, ProposerKey, DEVNET_CHAIN_ID};
use ubi2_runtime::Account;

const GENESIS_TIME: u64 = 1_700_000_000;
const DEV_ADDR: alloy_primitives::Address = address!("f39Fd6e51aad88F6F4ce6aB8827279cffFb92266");
/// The multi-node devnet's designated proposer (Anvil acct #2) — the pinned PoA validator.
const DESIGNATED_PROPOSER: alloy_primitives::Address =
    address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC");
/// Anvil acct #2 secret (PUBLIC, non-secret devnet key) — derives `DESIGNATED_PROPOSER`.
const PROPOSER_SECRET: [u8; 32] =
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
const DEVNET_JURORS: [alloy_primitives::Address; 3] = [
    address!("70997970C51812dc3A010C7d01b50e0d17dc79C8"),
    address!("3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"),
    address!("90F79bf6EB2c4f870365E785982E1f101E93b906"),
];
const DEVNET_CSCA_KEY_ID: [u8; 32] = [0xC5; 32];
const DEVNET_CSCA_PUBKEY: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

// ---- The PINNED constants shipped in apps/light-node/src/config.ts ----
const PINNED_GENESIS_HASH: &str =
    "b24d054faa31dc8e98ada4955a101f49528b708546f45558c9f45f7a9913779c";
const PINNED_GENESIS_STATE_ROOT: &str =
    "aa2c66cdd242eed1c3f1fa7511d60b9bc67099f6ffcaa1a8045bc25202bc1d0d";

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nibble(b[i * 2]) << 4) | nibble(b[i * 2 + 1]);
        i += 1;
    }
    out
}
const fn nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Build the canonical devnet genesis (the SAME seeds `main.rs` applies on a fresh boot) and seal the
/// anchor, returning the (genesis_hash, genesis_state_root) hex strings.
fn canonical_anchor() -> (String, String) {
    let key = Arc::new(ProposerKey::from_bytes(&PROPOSER_SECRET).expect("proposer key"));
    assert_eq!(
        key.address(),
        DESIGNATED_PROPOSER,
        "proposer secret derives the designated proposer"
    );
    let chain = Chain::new(DEVNET_CHAIN_ID, GENESIS_TIME).with_proposer_key(key);

    // SAME genesis seeds as crates/node/src/main.rs (fresh path).
    chain.seed_account(Account {
        address: DEV_ADDR.into_array(),
        verified: true,
        verified_at: GENESIS_TIME,
        last_settled_at: GENESIS_TIME,
        settled_balance: 0,
        nonce: 0,
    });
    chain.seed_verified_human(&DEV_ADDR.into_array(), GENESIS_TIME);
    for j in DEVNET_JURORS {
        chain.register_juror(&j.into_array(), 0);
    }
    chain.set_csca_governance(&DEV_ADDR.into_array());
    chain.seed_csca(*b"USA", DEVNET_CSCA_KEY_ID, DEVNET_CSCA_PUBKEY.to_vec());
    chain.seal_genesis();

    (
        hex(chain.genesis_hash().as_slice()),
        hex(chain.genesis_state_root().expect("sealed").as_slice()),
    )
}

#[test]
fn shipped_config_pins_the_canonical_devnet_genesis_anchor() {
    let (hash, root) = canonical_anchor();
    assert_eq!(
        hash, PINNED_GENESIS_HASH,
        "genesis HASH drifted from the pinned constant in apps/light-node/src/config.ts — re-pin it"
    );
    assert_eq!(
        root, PINNED_GENESIS_STATE_ROOT,
        "seeded genesis STATE_ROOT drifted from the pinned constant in apps/light-node/src/config.ts — re-pin it"
    );
}
