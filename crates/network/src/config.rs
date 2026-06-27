//! Network configuration — ports, bootstrap peers, keys, and chain identity (the node-wiring surface).
//!
//! The node builds a [`NetworkConfig`] from its CLI/env and passes it to [`crate::NetworkHandle::start`].
//! Two identities are distinct (ADR Decision 3): the **libp2p Ed25519 keypair** (the transport `PeerId`)
//! and the optional **validator EVM secp256k1 key** (signs the `Hello` peer-proof and, in the node,
//! blocks/verdicts). A non-validator node leaves `validator_key` `None` and still relays gossip.

use std::time::Duration;

use libp2p::identity::Keypair;
use libp2p::Multiaddr;

use crate::wire::Hash;

/// The local validator signing key (secp256k1), used only to sign the `Hello` peer-proof here. The
/// node owns the same key (it also signs blocks); the network never holds the runtime/chain — it just
/// needs to prove `PeerId` speaks for this validator address (§4.1, ADR Decision 3).
#[derive(Clone)]
pub struct ValidatorKey {
    signing_key: k256::ecdsa::SigningKey,
    address: alloy_primitives::Address,
}

impl std::fmt::Debug for ValidatorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("ValidatorKey")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl ValidatorKey {
    /// Build from 32 raw secret bytes, deriving the EVM address (`keccak256(pubkey)[12..]`). Matches
    /// `rpc::ProposerKey::from_bytes` so the same devnet key yields the same address on both sides.
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, String> {
        let signing_key =
            k256::ecdsa::SigningKey::from_slice(secret).map_err(|e| format!("bad key: {e}"))?;
        let vk = signing_key.verifying_key();
        let p = vk.to_encoded_point(false);
        let h = alloy_primitives::keccak256(&p.as_bytes()[1..]);
        let address = alloy_primitives::Address::from_slice(&h[12..]);
        Ok(ValidatorKey {
            signing_key,
            address,
        })
    }

    /// The validator's EVM address.
    pub fn address(&self) -> alloy_primitives::Address {
        self.address
    }

    /// Sign a 32-byte digest, returning the 65-byte `r‖s‖v` signature (`v = 27 + recid`) — the encoding
    /// [`crate::wire::recover_secp256k1`] expects.
    pub fn sign_digest(&self, digest: &Hash) -> Vec<u8> {
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(digest.as_slice())
            .expect("sign 32-byte prehash");
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.r().to_bytes());
        out.extend_from_slice(&sig.s().to_bytes());
        out.push(27 + recid.to_byte());
        out
    }
}

/// Everything the network needs to start. Built by `crates/node`.
#[derive(Clone)]
pub struct NetworkConfig {
    /// The chain id (must match peers at the handshake, §4.1).
    pub chain_id: u64,
    /// The genesis block hash (must match peers at the handshake — wrong network ⇒ disconnect, §4.1).
    pub genesis_hash: Hash,
    /// The libp2p transport keypair (Ed25519 → `PeerId`). Generate a fresh one per node unless a stable
    /// identity is wanted (a bootstrap node usually pins its keypair so its multiaddr is stable).
    pub keypair: Keypair,
    /// The validator key, if this node is a validator (signs the `Hello` peer-proof). `None` ⇒ the node
    /// relays gossip but is not validator-trusted by peers.
    pub validator_key: Option<ValidatorKey>,
    /// The address(es) to listen on. Use a **non-default** port for devnet/tests (e.g.
    /// `/ip4/127.0.0.1/tcp/0` lets the OS pick a free port; the bound addr is reported on start).
    pub listen_addrs: Vec<Multiaddr>,
    /// Static bootstrap peers to dial on start (multiaddrs, ideally `/p2p/<peerid>`-suffixed). Explicit
    /// dial works WITHOUT mDNS, so tests are deterministic (§1, ADR Decision 1).
    pub bootstrap_peers: Vec<Multiaddr>,
    /// Enable mDNS local-network discovery (the devnet convenience). Tests set this `false` and rely on
    /// explicit `bootstrap_peers` / `dial` so connectivity is deterministic.
    pub enable_mdns: bool,
    /// gossipsub heartbeat interval. Lower = faster mesh formation (good for tests); default 1s.
    pub gossip_heartbeat: Duration,
}

impl NetworkConfig {
    /// A minimal config: a fresh transport keypair, one OS-assigned TCP listener, no bootstrap, mDNS off
    /// (deterministic). Callers set `bootstrap_peers` / `validator_key` / `enable_mdns` as needed.
    pub fn new(chain_id: u64, genesis_hash: Hash) -> Self {
        NetworkConfig {
            chain_id,
            genesis_hash,
            keypair: Keypair::generate_ed25519(),
            validator_key: None,
            listen_addrs: vec!["/ip4/127.0.0.1/tcp/0"
                .parse()
                .expect("valid loopback multiaddr")],
            bootstrap_peers: Vec::new(),
            enable_mdns: false,
            gossip_heartbeat: Duration::from_secs(1),
        }
    }

    /// Set the libp2p transport keypair (e.g. a pinned bootstrap-node identity).
    pub fn with_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = keypair;
        self
    }
    /// Attach the validator key (sign the `Hello` peer-proof; advertise this node as a validator).
    pub fn with_validator_key(mut self, key: ValidatorKey) -> Self {
        self.validator_key = Some(key);
        self
    }
    /// Replace the listen addresses.
    pub fn with_listen_addrs(mut self, addrs: Vec<Multiaddr>) -> Self {
        self.listen_addrs = addrs;
        self
    }
    /// Replace the static bootstrap-peer list.
    pub fn with_bootstrap_peers(mut self, peers: Vec<Multiaddr>) -> Self {
        self.bootstrap_peers = peers;
        self
    }
    /// Enable/disable mDNS discovery.
    pub fn with_mdns(mut self, on: bool) -> Self {
        self.enable_mdns = on;
        self
    }
    /// Set the gossipsub heartbeat interval.
    pub fn with_gossip_heartbeat(mut self, d: Duration) -> Self {
        self.gossip_heartbeat = d;
        self
    }
}
