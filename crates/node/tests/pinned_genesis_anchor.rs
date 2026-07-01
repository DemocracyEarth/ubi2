//! Regression guard for the SHIPPED light-client pinned genesis anchor (spec 07 §3.4, `ln-trust-1/2/3`).
//!
//! The browser app (`apps/light-node/src/config.ts`) carries HARD-CODED genesis anchor constants — the
//! genesis hash, the seeded genesis `state_root`, and the authorized PoA proposer — derived from the
//! canonical devnet genesis (`genesis_time = 1700000000`). If the genesis seeding ever changes (a new
//! seeded account, a different CSCA, a changed juror set, a `state_root` format bump, …) those pinned
//! constants would silently go stale and the shipped app would reject EVERY honest gateway (or, worse,
//! fail to catch a lying one). This test recomputes the canonical anchor from the SAME seeds `main.rs`
//! applies — via the SHARED `ubi2_node::canonical_devnet_genesis` (the single source of truth for the
//! genesis seed list, also used by `ubi genesis anchor`) — and asserts it equals the pinned constants,
//! so such a drift fails CI with a clear pointer to re-pin `config.ts`.
//!
//! Because both this test and the live node seed through `ubi2_node::seed_canonical_devnet_genesis`,
//! there is no duplicated seed list to drift: a seed change updates the anchor everywhere at once, and
//! this test simply asserts the app's PINNED constants track it.
//!
//! KEEP IN SYNC with `apps/light-node/src/config.ts` (the pinned constants).

use ubi2_node::canonical_devnet_genesis;

const GENESIS_TIME: u64 = 1_700_000_000;
/// Anvil acct #2 secret (PUBLIC, non-secret devnet key) — derives the pinned PoA proposer
/// `0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC`. Attaching it must NOT change the anchor.
const PROPOSER_SECRET: [u8; 32] =
    hex32("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");

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

#[test]
fn shipped_config_pins_the_canonical_devnet_genesis_anchor() {
    // Seed + seal via the SHARED canonical genesis (the exact seed list the live node applies).
    let (hash, root) = canonical_devnet_genesis(GENESIS_TIME, Some(PROPOSER_SECRET));
    assert_eq!(
        hash, PINNED_GENESIS_HASH,
        "genesis HASH drifted from the pinned constant in apps/light-node/src/config.ts — re-pin it"
    );
    assert_eq!(
        root, PINNED_GENESIS_STATE_ROOT,
        "seeded genesis STATE_ROOT drifted from the pinned constant in apps/light-node/src/config.ts — re-pin it"
    );

    // The anchor is a pure function of the seeds + genesis time: with or without the proposer key
    // attached it is identical (the key only makes `genesis_proposer()` resolve).
    let (hash_no_key, root_no_key) = canonical_devnet_genesis(GENESIS_TIME, None);
    assert_eq!(hash_no_key, PINNED_GENESIS_HASH);
    assert_eq!(root_no_key, PINNED_GENESIS_STATE_ROOT);
}
