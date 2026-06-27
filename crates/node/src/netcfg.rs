//! M5 Stage A — the node's networking config, resolved from env vars.
//!
//! The multi-node devnet (`scripts/devnet-multi.sh`) sets these per process. Keys are PUBLIC devnet keys
//! (Anvil accounts) — NEVER secrets. Defaults keep the single-node M1–M4 devnet boot unchanged: with no
//! `UBI2_P2P_ADDR` the node runs networkless exactly as before.

use std::time::Duration;

use alloy_primitives::Address as AlloyAddr;
use libp2p::identity::Keypair;
use libp2p::Multiaddr;
use ubi2_network::config::NetworkConfig;
use ubi2_network::ValidatorKey;
use ubi2_rpc::ProposerKey;

/// Resolved node-network config. `None` listen addr ⇒ networking disabled (legacy single-node devnet).
pub struct NodeNetConfig {
    /// The libp2p config to start the swarm with (only built when networking is enabled).
    pub network: Option<NetworkConfig>,
    /// This node's proposer signing-key secret bytes, if it is the designated proposer (it produces +
    /// signs blocks). Main constructs the `ProposerKey`/`Arc` from these. PUBLIC devnet key — not secret.
    pub proposer_secret: Option<[u8; 32]>,
    /// The validator key (signs the `Hello` peer-proof). Defaults to the proposer key's bytes when this
    /// node is the proposer; a follower may still set one to advertise itself as a validator.
    pub validator_key: Option<ValidatorKey>,
    /// The Stage-A designated proposer address every node validates blocks against (AC-F3).
    pub designated_proposer: Option<AlloyAddr>,
    /// True iff THIS node is the designated proposer.
    pub is_proposer: bool,
    /// The pinned genesis unix time, shared by every node so genesis hashes match (the network anchor).
    pub genesis_time: u64,
    /// How often the proposer ticks / the tx-relay fires (block interval), ms.
    pub block_ms: u64,
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|s| !s.trim().is_empty())
}

/// Parse a 32-byte hex secret (with or without `0x`).
fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Parse a 20-byte hex address (with or without `0x`).
fn parse_addr(s: &str) -> Option<AlloyAddr> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 40 {
        return None;
    }
    let mut out = [0u8; 20];
    for i in 0..20 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(AlloyAddr::from(out))
}

/// Build a stable libp2p Ed25519 keypair from a 32-byte seed (so a bootstrap node's PeerId — and thus
/// its `/p2p/<id>` multiaddr — is predictable across restarts). Absent a seed, a fresh keypair is used.
fn keypair_from_seed(seed: Option<[u8; 32]>) -> Keypair {
    match seed {
        Some(mut bytes) => {
            Keypair::ed25519_from_bytes(&mut bytes).unwrap_or_else(|_| Keypair::generate_ed25519())
        }
        None => Keypair::generate_ed25519(),
    }
}

/// The base58 libp2p `PeerId` derived from a 32-byte hex Ed25519 seed (the `ubi2-node peer-id <seed>`
/// utility). Pure — derives the keypair and prints its PeerId without any networking. Used by the
/// multi-node devnet script to precompute every node's PeerId for a deterministic cross-bootstrap mesh.
pub fn peer_id_for_seed_hex(seed_hex: &str) -> Result<String, String> {
    let seed = parse_hex32(seed_hex).ok_or("seed must be 32-byte hex (64 hex chars)")?;
    let kp = keypair_from_seed(Some(seed));
    Ok(libp2p::PeerId::from(kp.public()).to_base58())
}

/// Resolve the node-network config from env. Recognized vars (all optional):
///
/// - `UBI2_GENESIS_TIME`: pinned genesis unix seconds (shared across nodes). Default: now.
/// - `UBI2_BLOCK_MS`: block / relay tick ms. Default 2000.
/// - `UBI2_P2P_ADDR`: libp2p listen multiaddr (e.g. `/ip4/127.0.0.1/tcp/19001`). Its presence ENABLES
///   networking; its absence keeps the legacy single-node devnet.
/// - `UBI2_BOOTSTRAP`: comma-separated bootstrap multiaddrs to dial.
/// - `UBI2_P2P_SEED`: 32-byte hex Ed25519 seed for a stable PeerId.
/// - `UBI2_PROPOSER_KEY`: 32-byte hex secp256k1 secret. Its presence makes THIS node the proposer.
/// - `UBI2_DESIGNATED_PROPOSER`: 20-byte hex address every follower validates blocks against; defaults
///   to the proposer key's address on the proposer node.
/// - `UBI2_VALIDATOR_KEY`: 32-byte hex secp256k1 secret for the Hello peer-proof; defaults to the
///   proposer key when this node is the proposer.
/// - `UBI2_MDNS`: `1`/`true` to enable mDNS local discovery (off by default — deterministic).
pub fn resolve(default_genesis_time: u64) -> NodeNetConfig {
    let genesis_time = env("UBI2_GENESIS_TIME")
        .and_then(|s| s.parse().ok())
        .unwrap_or(default_genesis_time);
    let block_ms = env("UBI2_BLOCK_MS")
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);

    let proposer_secret = env("UBI2_PROPOSER_KEY").and_then(|s| parse_hex32(&s));
    // Validate the key parses to an address (and capture it for the designated-proposer default).
    let proposer_addr = proposer_secret
        .and_then(|b| ProposerKey::from_bytes(&b).ok())
        .map(|k| k.address());
    let is_proposer = proposer_addr.is_some();

    // The designated proposer: explicit env, else (if we are the proposer) our own address.
    let designated_proposer = env("UBI2_DESIGNATED_PROPOSER")
        .and_then(|s| parse_addr(&s))
        .or(proposer_addr);

    // Validator key for the Hello peer-proof: explicit, else the proposer key bytes (so the bound
    // validator address == the designated proposer's address on the proposer node).
    let validator_key = env("UBI2_VALIDATOR_KEY")
        .and_then(|s| parse_hex32(&s))
        .or_else(|| env("UBI2_PROPOSER_KEY").and_then(|s| parse_hex32(&s)))
        .and_then(|b| ValidatorKey::from_bytes(&b).ok());

    let network = env("UBI2_P2P_ADDR").map(|listen| {
        let listen_addr: Multiaddr = listen.parse().unwrap_or_else(|e| {
            panic!("UBI2_P2P_ADDR `{listen}` is not a valid multiaddr: {e}");
        });
        let bootstrap: Vec<Multiaddr> = env("UBI2_BOOTSTRAP")
            .map(|raw| {
                raw.split(',')
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .filter_map(|s| s.parse().ok())
                    .collect()
            })
            .unwrap_or_default();
        let seed = env("UBI2_P2P_SEED").and_then(|s| parse_hex32(&s));
        let enable_mdns = env("UBI2_MDNS")
            .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        // We need the genesis hash for the Hello, but it depends on genesis_time only (an empty-state
        // genesis). The node fills it via `NetworkConfig`'s `genesis_hash`; main passes the chain's real
        // genesis hash after constructing the chain. Here we leave a placeholder set by main.
        let mut cfg = NetworkConfig::new(ubi2_rpc::DEVNET_CHAIN_ID, alloy_primitives::B256::ZERO)
            .with_keypair(keypair_from_seed(seed))
            .with_listen_addrs(vec![listen_addr])
            .with_bootstrap_peers(bootstrap)
            .with_mdns(enable_mdns)
            .with_gossip_heartbeat(Duration::from_millis(500));
        if let Some(vk) = &validator_key {
            cfg = cfg.with_validator_key(vk.clone());
        }
        cfg
    });

    NodeNetConfig {
        network,
        proposer_secret,
        validator_key,
        designated_proposer,
        is_proposer,
        genesis_time,
        block_ms,
    }
}
