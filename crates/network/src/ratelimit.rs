//! Per-peer anti-spam: a token-bucket rate limiter + an invalid-message counter (FU-1, spec §3.3).
//!
//! These are the *application-level* defenses that sit on top of gossipsub's transport-level peer
//! scoring (ADR Decision 1): libp2p cannot know our tx/block validity rules, so the node tells the
//! limiter when a peer sent something invalid, and the limiter throttles/greylists abusers.
//!
//! Pure, integer, deterministic given an explicit `now` (no wall-clock read here — the swarm loop
//! passes the monotonic clock), so it is unit-testable. Bounded memory: one small struct per peer.

use std::collections::HashMap;
use std::time::Instant;

use libp2p::PeerId;

use crate::consts::{
    RATE_BUCKET_CAPACITY, RATE_REFILL_PER_SEC, SYNC_MAX_INFLIGHT_PER_PEER,
    SYNC_RATE_BUCKET_CAPACITY, SYNC_RATE_REFILL_PER_SEC,
};

/// A single token bucket (fixed-point tokens × 1000 for integer-exact per-ms refill).
#[derive(Debug, Clone)]
struct TokenBucket {
    tokens_milli: u64,
    last_refill: Instant,
    capacity: u32,
    refill_per_sec: u32,
}

impl TokenBucket {
    fn new(now: Instant, capacity: u32, refill_per_sec: u32) -> Self {
        TokenBucket {
            tokens_milli: capacity as u64 * 1000,
            last_refill: now,
            capacity,
            refill_per_sec,
        }
    }
    fn refill(&mut self, now: Instant) {
        let elapsed_ms = now.saturating_duration_since(self.last_refill).as_millis() as u64;
        if elapsed_ms == 0 {
            return;
        }
        let add = elapsed_ms * self.refill_per_sec as u64; // tokens_milli per ms = refill_per_sec
        let cap = self.capacity as u64 * 1000;
        self.tokens_milli = (self.tokens_milli + add).min(cap);
        self.last_refill = now;
    }
    /// Charge one token; `true` if one was available (admit), `false` if empty (drop).
    fn take(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens_milli >= 1000 {
            self.tokens_milli -= 1000;
            true
        } else {
            false
        }
    }
}

/// One peer's buckets + abuse counters.
#[derive(Debug, Clone)]
struct PeerBucket {
    /// Inbound gossip (tx/block) bucket (FU-1, §3.3).
    gossip: TokenBucket,
    /// Inbound SYNC/Hello request-response bucket (SEC-M5A-2) — independent of the gossip bucket so a
    /// healthy join-sync burst does not starve gossip and a sync flood is throttled on its own budget.
    sync: TokenBucket,
    /// In-flight inbound `GetBlocks` requests currently being serviced for this peer (SEC-M5A-2). Capped
    /// by [`SYNC_MAX_INFLIGHT_PER_PEER`]; incremented on accept, decremented when the response is sent or
    /// the request is dropped.
    sync_inflight: usize,
    /// Count of invalid messages this peer has sent (gossip we validated and rejected). Drives the
    /// greylist decision; the node also lowers the gossipsub peer score on each.
    invalid_count: u32,
}

impl PeerBucket {
    fn new(now: Instant) -> Self {
        PeerBucket {
            gossip: TokenBucket::new(now, RATE_BUCKET_CAPACITY, RATE_REFILL_PER_SEC),
            sync: TokenBucket::new(now, SYNC_RATE_BUCKET_CAPACITY, SYNC_RATE_REFILL_PER_SEC),
            sync_inflight: 0,
            invalid_count: 0,
        }
    }
}

/// Number of invalid messages from a peer before it is greylisted (dropped/ignored). A small, fixed
/// threshold — a single typo costs nothing; a flood of invalid gossip gets the peer cut off (§3.3).
pub const GREYLIST_THRESHOLD: u32 = 16;

/// A per-peer token-bucket limiter. Constructed once per swarm; the loop calls [`Self::allow`] on each
/// inbound gossip message and [`Self::penalize`] when the node rejects a message as invalid.
#[derive(Debug, Default)]
pub struct RateLimiter {
    peers: HashMap<PeerId, PeerBucket>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            peers: HashMap::new(),
        }
    }

    /// Charge one token for an inbound GOSSIP message from `peer` at `now`. Returns `true` if within rate
    /// (admit + process), `false` if the gossip bucket is empty (drop — do not process/forward).
    pub fn allow(&mut self, peer: &PeerId, now: Instant) -> bool {
        let b = self
            .peers
            .entry(*peer)
            .or_insert_with(|| PeerBucket::new(now));
        b.gossip.take(now)
    }

    /// SEC-M5A-2: charge one token for an inbound SYNC/Hello request from `peer`. Returns `true` if within
    /// the sync rate (service it), `false` if the sync bucket is empty (drop — do not service). Keeps the
    /// previously-unbounded request-response path on a per-peer budget.
    pub fn allow_sync(&mut self, peer: &PeerId, now: Instant) -> bool {
        let b = self
            .peers
            .entry(*peer)
            .or_insert_with(|| PeerBucket::new(now));
        b.sync.take(now)
    }

    /// SEC-M5A-2: try to reserve an in-flight slot for an inbound `GetBlocks` from `peer`. Returns `true`
    /// (and increments the in-flight count) if under [`SYNC_MAX_INFLIGHT_PER_PEER`], else `false` (the
    /// request is dropped). Pair every `true` with exactly one [`Self::release_sync_inflight`].
    pub fn try_acquire_sync_inflight(&mut self, peer: &PeerId, now: Instant) -> bool {
        let b = self
            .peers
            .entry(*peer)
            .or_insert_with(|| PeerBucket::new(now));
        if b.sync_inflight >= SYNC_MAX_INFLIGHT_PER_PEER {
            return false;
        }
        b.sync_inflight += 1;
        true
    }

    /// SEC-M5A-2: release an in-flight sync slot previously reserved by
    /// [`Self::try_acquire_sync_inflight`] (on response-sent or request-dropped).
    pub fn release_sync_inflight(&mut self, peer: &PeerId) {
        if let Some(b) = self.peers.get_mut(peer) {
            b.sync_inflight = b.sync_inflight.saturating_sub(1);
        }
    }

    /// Record that `peer` sent an invalid message (the node validated + rejected it). Returns `true` if
    /// the peer has now crossed [`GREYLIST_THRESHOLD`] and should be disconnected/greylisted (§3.3).
    pub fn penalize(&mut self, peer: &PeerId, now: Instant) -> bool {
        let b = self
            .peers
            .entry(*peer)
            .or_insert_with(|| PeerBucket::new(now));
        b.invalid_count = b.invalid_count.saturating_add(1);
        b.invalid_count >= GREYLIST_THRESHOLD
    }

    /// The invalid-message count for `peer` (0 if unknown) — surfaced for peer-score reporting/tests.
    pub fn invalid_count(&self, peer: &PeerId) -> u32 {
        self.peers.get(peer).map(|b| b.invalid_count).unwrap_or(0)
    }

    /// Forget a peer's state on disconnect (bounded memory).
    pub fn forget(&mut self, peer: &PeerId) {
        self.peers.remove(peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn bucket_admits_burst_then_throttles_then_refills() {
        let mut rl = RateLimiter::new();
        let peer = PeerId::random();
        let t0 = Instant::now();
        // Burst the full capacity — all admitted.
        for _ in 0..RATE_BUCKET_CAPACITY {
            assert!(rl.allow(&peer, t0));
        }
        // Next one over an empty bucket at the same instant is throttled.
        assert!(!rl.allow(&peer, t0));
        // After 1s the bucket refilled RATE_REFILL_PER_SEC tokens.
        let t1 = t0 + Duration::from_secs(1);
        for _ in 0..RATE_REFILL_PER_SEC {
            assert!(rl.allow(&peer, t1));
        }
        assert!(!rl.allow(&peer, t1));
    }

    #[test]
    fn penalize_greylists_after_threshold() {
        let mut rl = RateLimiter::new();
        let peer = PeerId::random();
        let now = Instant::now();
        for i in 1..GREYLIST_THRESHOLD {
            assert!(!rl.penalize(&peer, now), "not greylisted at {i}");
        }
        assert!(rl.penalize(&peer, now), "greylisted at threshold");
        assert_eq!(rl.invalid_count(&peer), GREYLIST_THRESHOLD);
        rl.forget(&peer);
        assert_eq!(rl.invalid_count(&peer), 0);
    }

    /// SEC-M5A-2: the inbound SYNC/Hello bucket is INDEPENDENT of the gossip bucket and throttles a flood
    /// of sync requests on its own per-peer budget — exhausting one bucket does not affect the other.
    #[test]
    fn sync_bucket_is_independent_and_throttles() {
        let mut rl = RateLimiter::new();
        let peer = PeerId::random();
        let t0 = Instant::now();

        // Burst the full sync capacity — all admitted; the next over an empty bucket is throttled.
        for _ in 0..SYNC_RATE_BUCKET_CAPACITY {
            assert!(
                rl.allow_sync(&peer, t0),
                "sync request within capacity is serviced"
            );
        }
        assert!(
            !rl.allow_sync(&peer, t0),
            "a sync flood over the bucket is throttled (SEC-M5A-2)"
        );
        // The gossip bucket is untouched by the sync flood — independent budgets.
        assert!(
            rl.allow(&peer, t0),
            "gossip bucket is independent of the (exhausted) sync bucket"
        );

        // After 1s the sync bucket refilled SYNC_RATE_REFILL_PER_SEC tokens.
        let t1 = t0 + Duration::from_secs(1);
        for _ in 0..SYNC_RATE_REFILL_PER_SEC {
            assert!(rl.allow_sync(&peer, t1));
        }
        assert!(
            !rl.allow_sync(&peer, t1),
            "sync bucket throttles again once drained"
        );
    }

    /// SEC-M5A-2: concurrent in-flight `GetBlocks` per peer is capped; a request over the cap is refused,
    /// and releasing a slot frees capacity again.
    #[test]
    fn sync_inflight_is_capped_per_peer() {
        let mut rl = RateLimiter::new();
        let peer = PeerId::random();
        let now = Instant::now();
        for i in 0..SYNC_MAX_INFLIGHT_PER_PEER {
            assert!(
                rl.try_acquire_sync_inflight(&peer, now),
                "slot {i} within the cap is acquired"
            );
        }
        assert!(
            !rl.try_acquire_sync_inflight(&peer, now),
            "a request over SYNC_MAX_INFLIGHT_PER_PEER is refused"
        );
        // Releasing one frees exactly one slot.
        rl.release_sync_inflight(&peer);
        assert!(
            rl.try_acquire_sync_inflight(&peer, now),
            "a freed slot is reusable"
        );
    }
}
