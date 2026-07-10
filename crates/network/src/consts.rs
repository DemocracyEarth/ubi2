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

/// Maximum number of blocks a peer-advertised tip may be ahead of our local head before we treat the
/// advertisement as implausible and REFUSE to chase it (SEC-M5A-1). A forged announcement claiming
/// `number = u64::MAX` would otherwise pin a bogus tip and drive an unbounded sync loop. We sync toward
/// a peer that is plausibly ahead — many full sync batches' worth of headroom — but never toward an
/// arbitrary attacker-chosen height. A genuinely far-behind node still catches up batch-by-batch: each
/// applied batch advances the local head, which re-bounds the next acceptable look-ahead.
pub const SYNC_MAX_LOOKAHEAD: u64 = SYNC_MAX_BATCH * 64; // 8192 blocks of headroom

/// How many consecutive sync responses that make ZERO forward progress (applied 0 blocks) we tolerate
/// from a peer before abandoning + penalizing it (SEC-M5A-1). A peer that advertised a tip it cannot
/// actually serve — or that keeps replying empty/timeout — must not drive an unbounded re-request loop.
/// After this many no-progress rounds the peer is penalized (counting toward the greylist threshold) and
/// we stop chasing its advertised tip until it advertises a higher one again via a fresh, progressing
/// response.
pub const SYNC_MAX_NO_PROGRESS_ROUNDS: u32 = 3;

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

/// Per-peer token-bucket capacity for inbound SYNC/Hello request-response messages (SEC-M5A-2). The
/// sync path (`GetBlocks`/`Hello`) was previously un-rate-limited, so a peer could flood expensive
/// range requests unboundedly. This bucket throttles it independently of the gossip bucket. Sized for a
/// healthy join-sync burst (genesis→tip is many `GetBlocks` in quick succession) while still cutting off
/// a flood; over-rate requests are dropped (not serviced) and count toward the greylist threshold.
pub const SYNC_RATE_BUCKET_CAPACITY: u32 = 64;

/// Per-peer refill rate (tokens per second) for the inbound SYNC/Hello bucket (SEC-M5A-2).
pub const SYNC_RATE_REFILL_PER_SEC: u32 = 16;

/// Max concurrent in-flight inbound SYNC (`GetBlocks`) requests we will service for a single peer at
/// once (SEC-M5A-2). A peer opening many simultaneous range streams to exhaust us is capped here: a
/// request over the cap is dropped (the channel is let drop, so the requester sees a failure) and the
/// peer penalized. A response (or its channel drop) releases a slot. `Hello` handshakes are not counted
/// (they are cheap and one-per-connection).
pub const SYNC_MAX_INFLIGHT_PER_PEER: usize = 4;

/// Protocol version exchanged in the `Hello` handshake (spec §4.1 `protocol_ver`). A peer with a
/// different major version is treated as incompatible and disconnected (`on_hello`, spec 08 §9). Bumped
/// `1 → 2` for M5 Stage B: the block payload on `ubi2/block/1` is redefined in place to carry the header
/// `view` field (§2.2/§9) — the topic/sync strings are UNCHANGED, so the version bump is the loud,
/// explicit break that stops an old node silently mis-decoding a new (view-carrying) block.
pub const PROTOCOL_VERSION: u16 = 2;

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
