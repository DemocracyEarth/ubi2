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

use crate::consts::{RATE_BUCKET_CAPACITY, RATE_REFILL_PER_SEC};

/// One peer's bucket + abuse counters.
#[derive(Debug, Clone)]
struct PeerBucket {
    /// Available tokens (fixed-point: tokens × 1000, so the refill is integer-exact per ms).
    tokens_milli: u64,
    /// Last refill timestamp.
    last_refill: Instant,
    /// Count of invalid messages this peer has sent (gossip we validated and rejected). Drives the
    /// greylist decision; the node also lowers the gossipsub peer score on each.
    invalid_count: u32,
}

impl PeerBucket {
    fn new(now: Instant) -> Self {
        PeerBucket {
            tokens_milli: RATE_BUCKET_CAPACITY as u64 * 1000,
            last_refill: now,
            invalid_count: 0,
        }
    }
    fn refill(&mut self, now: Instant) {
        let elapsed_ms = now.saturating_duration_since(self.last_refill).as_millis() as u64;
        if elapsed_ms == 0 {
            return;
        }
        let add = elapsed_ms * RATE_REFILL_PER_SEC as u64; // tokens_milli per ms = refill_per_sec
        let cap = RATE_BUCKET_CAPACITY as u64 * 1000;
        self.tokens_milli = (self.tokens_milli + add).min(cap);
        self.last_refill = now;
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

    /// Charge one token for an inbound message from `peer` at `now`. Returns `true` if the message is
    /// within rate (admit + process), `false` if the bucket is empty (drop — do not process/forward).
    pub fn allow(&mut self, peer: &PeerId, now: Instant) -> bool {
        let b = self
            .peers
            .entry(*peer)
            .or_insert_with(|| PeerBucket::new(now));
        b.refill(now);
        if b.tokens_milli >= 1000 {
            b.tokens_milli -= 1000;
            true
        } else {
            false
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
}
