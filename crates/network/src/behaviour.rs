//! The composed libp2p [`NetworkBehaviour`]: gossipsub (two topics) + request-response (`ubi2/sync/1`)
//! + optional mDNS (spec §3–§4, ADR Decision 1).
//!
//! The `#[derive(NetworkBehaviour)]` macro fuses the three sub-behaviours into one and generates a
//! `Ubi2BehaviourEvent` enum the swarm loop matches on. mDNS is wrapped in a [`Toggle`] so it can be
//! disabled (tests use explicit dial, not mDNS, for determinism — §1).

use std::time::Duration;

use libp2p::gossipsub::{self, MessageAuthenticity, MessageId, ValidationMode};
use libp2p::swarm::behaviour::toggle::Toggle;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{mdns, request_response, PeerId};

use crate::codec::{SyncCodec, SyncProtocol};
use crate::consts::{MAX_BLOCK_BYTES, PROTOCOL_SYNC, TOPIC_BLOCK, TOPIC_TX};
use crate::wire::WireBlock;

/// The request-response behaviour specialized to our sync codec.
pub type SyncBehaviour = request_response::Behaviour<SyncCodec>;

/// The fused ubi2 network behaviour.
#[derive(NetworkBehaviour)]
pub struct Ubi2Behaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub sync: SyncBehaviour,
    pub mdns: Toggle<mdns::tokio::Behaviour>,
}

impl Ubi2Behaviour {
    /// Build the behaviour from the local key + config knobs. `enable_mdns=false` yields a disabled
    /// `Toggle` (deterministic tests dial explicitly).
    pub fn new(
        key: &libp2p::identity::Keypair,
        local_peer_id: PeerId,
        gossip_heartbeat: Duration,
        enable_mdns: bool,
    ) -> Result<Self, String> {
        // gossipsub: sign messages with the node's transport key (authenticated origin), and set the
        // message-id to the **content address the chain already uses** (spec §3.1): for a tx the id is
        // `keccak256(rlp)` = the tx hash; for a block the id is the **block hash** = `keccak256(header
        // pre-image)`, NOT `keccak256(full_block_bytes)` — the encoded block payload carries the txs +
        // sig, so we decode the header and hash the pre-image so two nodes announcing the same block
        // produce the identical id (free, correct dedup). A malformed block payload falls back to a
        // payload hash (it will be dropped at the application layer anyway). `ValidationMode::Permissive`
        // accepts signed-or-unsigned messages; the application validates before re-broadcast (§3.2).
        let block_topic_hash = block_topic().hash();
        let message_id_fn = move |msg: &gossipsub::Message| {
            let h = if msg.topic == block_topic_hash {
                match WireBlock::decode(&msg.data) {
                    Ok(b) => b.hash(),
                    Err(_) => alloy_primitives::keccak256(&msg.data),
                }
            } else {
                alloy_primitives::keccak256(&msg.data)
            };
            MessageId::from(h.0.to_vec())
        };
        let gossip_cfg = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(gossip_heartbeat)
            .validation_mode(ValidationMode::Permissive)
            .message_id_fn(message_id_fn)
            // Bound a single gossip frame (anti-DoS); a block is the larger of the two payloads.
            .max_transmit_size(MAX_BLOCK_BYTES)
            .build()
            .map_err(|e| format!("gossipsub config: {e}"))?;
        let gossipsub =
            gossipsub::Behaviour::new(MessageAuthenticity::Signed(key.clone()), gossip_cfg)
                .map_err(|e| format!("gossipsub behaviour: {e}"))?;

        let sync = request_response::Behaviour::with_codec(
            SyncCodec,
            std::iter::once((
                SyncProtocol(PROTOCOL_SYNC),
                request_response::ProtocolSupport::Full,
            )),
            request_response::Config::default(),
        );

        let mdns = if enable_mdns {
            let m = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)
                .map_err(|e| format!("mdns behaviour: {e}"))?;
            Toggle::from(Some(m))
        } else {
            Toggle::from(None)
        };

        Ok(Ubi2Behaviour {
            gossipsub,
            sync,
            mdns,
        })
    }
}

/// The two gossipsub topics, parsed once (spec §3.1).
pub fn tx_topic() -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(TOPIC_TX)
}
pub fn block_topic() -> gossipsub::IdentTopic {
    gossipsub::IdentTopic::new(TOPIC_BLOCK)
}
