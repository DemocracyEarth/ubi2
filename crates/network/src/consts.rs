//! Network/consensus constants (spec `05-p2p-network.md` §10, devnet starting values).
//!
//! These mirror the spec's table 1:1. Only the networking-relevant subset is defined here; the
//! consensus-only constants (`EPOCH_BLOCKS`, `PROPOSER_TIMEOUT`, `FINALITY_DEPTH`, …) belong to the
//! node/runtime Stage-B work and are intentionally NOT duplicated in the transport crate.

/// gossipsub topic for pending transactions (raw EIP-155 tx bytes). Versioned via the `/1` suffix
/// (spec §3.1) — a format change is a new topic id, never a silent break.
pub const TOPIC_TX: &str = "ubi2/tx/1";

/// gossipsub topic for new blocks (canonically-encoded full block). Versioned via the `/1` suffix.
pub const TOPIC_BLOCK: &str = "ubi2/block/1";

/// libp2p request-response protocol id for block-range sync (spec §4.2). Versioned in the protocol
/// string — a wire change becomes a new protocol id.
pub const PROTOCOL_SYNC: &str = "/ubi2/sync/1";

/// Max blocks returned by a single `GetBlocks`/`Blocks` exchange (spec §10, `SYNC_MAX_BATCH`). Bounds
/// sync-response size (the range-request DoS defense, §4.2/AC-F8). A `GetBlocks` whose `to − from + 1`
/// exceeds this is clamped by the server before it reads blocks.
pub const SYNC_MAX_BATCH: u64 = 128;

/// Global mempool cap (spec §10, `MEMPOOL_MAX_TXS`). Enforced by the node's mempool; surfaced here as
/// the canonical value so the rate-limit/anti-spam hooks and the node agree on one number.
pub const MEMPOOL_MAX_TXS: usize = 4096;

/// Per-sender mempool cap (spec §10, `MEMPOOL_MAX_PER_SENDER`).
pub const MEMPOOL_MAX_PER_SENDER: usize = 64;

/// Per-peer token-bucket capacity for inbound gossip messages (FU-1, §3.3). A peer may burst up to this
/// many messages; the bucket refills at [`RATE_REFILL_PER_SEC`]. A message arriving on an empty bucket
/// is dropped (not forwarded) and counts toward the peer's invalid-rate score.
pub const RATE_BUCKET_CAPACITY: u32 = 256;

/// Per-peer token-bucket refill rate (tokens per second) for inbound gossip (FU-1, §3.3).
pub const RATE_REFILL_PER_SEC: u32 = 64;

/// Protocol version exchanged in the `Hello` handshake (spec §4.1 `protocol_ver`). A peer with a
/// different major version is treated as incompatible.
pub const PROTOCOL_VERSION: u16 = 1;

/// Max accepted size (bytes) of a single gossiped tx payload — a coarse anti-DoS bound on the raw RLP.
/// A larger payload is dropped before hashing (malformed/abusive). Generous vs. real EIP-155 txs.
pub const MAX_TX_BYTES: usize = 128 * 1024;

/// Max accepted size (bytes) of a single gossiped block payload. Bounds a block's encoded size; a
/// larger announcement is dropped. Generous vs. a full devnet block.
pub const MAX_BLOCK_BYTES: usize = 8 * 1024 * 1024;

/// How often the swarm runs its bootstrap-reconnect sweep (§1 connectivity maintenance). On every tick
/// the swarm re-dials any configured bootstrap peer for which it currently has no live connection, so a
/// cold-start ordering race or a transient dial failure always converges to the full mesh. Kept short so
/// a node that lost (or never made) a connection heals quickly, independent of any fixed sleep in a test.
pub const RECONNECT_TICK_MS: u64 = 500;

/// The shortest reconnect backoff for a single bootstrap peer. After a failed/abandoned dial the swarm
/// waits at least this long before re-dialing that peer; the wait grows (capped at
/// [`RECONNECT_BACKOFF_MAX_MS`]) so a peer that is genuinely down is not hammered, while a peer that is
/// merely slow to start is reached promptly. The backoff resets to this floor on a successful connect.
pub const RECONNECT_BACKOFF_MIN_MS: u64 = 250;

/// The longest reconnect backoff for a single bootstrap peer (the cap on the exponential growth above).
/// Bounded so connectivity ALWAYS keeps retrying — there is no "give up" state — but never busy-loops.
/// Kept at 1 s (was 4 s) so that even after several cold-start dial failures the mesh converges within
/// a handful of seconds on a local network where peers start within milliseconds of each other.
pub const RECONNECT_BACKOFF_MAX_MS: u64 = 1_000;
