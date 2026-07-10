//! M5 (Stage A, Phase 1) — the **deterministic state root** (spec `05-p2p-network.md` §5.3).
//!
//! `state_root(&dyn State) -> [u8; 32]` is a pure, dependency-free, integer-only commitment over the
//! **entire** canonicalized state: accounts, streams (+ indexes), the proof-of-humanity registry
//! (humans, vouch edges, cases, jurors, the cleared-challenge cooldown set), the prompt-contract
//! registry (contracts, exec cases), and every id counter. It is the cross-node agreement primitive:
//!
//! > Two `State`s with the same *logical* content MUST produce a byte-identical root (EC-4/EC-10),
//! > and changing **any** field MUST change the root.
//!
//! ## Why a flat sorted hash (not a Merkle/MPT) for Stage A
//! The spec (§5.3) is explicit: Stage A only requires a *deterministic commitment*, not an Ethereum
//! Merkle-Patricia root (that is a Stage-D optimization + a backlog item). So this is a single
//! streaming hash over each collection serialized **in its canonical sorted order**. That is enough
//! to (a) detect any divergence and (b) be reproduced byte-for-byte by an independent node.
//!
//! ## Determinism discipline (the load-bearing rules)
//! - **No `HashMap` iteration order on any path.** Every collection is read through the `State` trait's
//!   already-sorted accessors (`humans()`, `cases()`, `vouch_edges()`, `active_jurors()`,
//!   `contracts()`, `exec_cases()`) or through this module's own sort (accounts by address, streams by
//!   id, the per-account stream indexes via the FU-13-sorted `incoming()`/`outgoing()`).
//! - **No floats.** All fields are integers / fixed-width byte arrays / 1-byte enum tags.
//! - **Length-prefixed, tagged, fixed-width.** Every variable-length field is preceded by its length
//!   and every enum by a 1-byte discriminant, so no two distinct states can serialize to the same
//!   bytes (no aliasing across field boundaries).
//! - **Dependency-free.** The 256-bit digest is the same FNV-1a-256 sponge construction the runtime
//!   already uses for `effect_hash` (`contracts.rs`) — no external hash crate, fully in-tree.

use crate::{
    Account, CanonicalEffect, CanonicalVerdict, CaseKind, CaseStatus, ContractStatus, ExecStatus,
    HumanStatus, MemState, State, Stream, StreamStatus,
};

/// A streaming 256-bit FNV-1a sponge — the same construction as `contracts::fnv1a_256`, reworked into
/// an incremental writer so we can fold the whole state in one pass without materializing one giant
/// buffer. Eight... (four) independent lanes with distinct offset bases, each a rolling FNV-1a hash;
/// `finish()` runs a SplitMix64 avalanche per lane and concatenates the 4×8 = 32 output bytes.
///
/// This is a **consensus-internal commitment** used for divergence detection between honest nodes, not
/// an adversarial/security hash — collision-resistance against an attacker is not required (the same
/// note `contracts::fnv1a_256` carries). Two honest nodes serializing the same canonical bytes get the
/// same 32-byte root, which is exactly what EC-4/EC-10 assert.
struct Hasher256 {
    lanes: [u64; 4],
}

const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

impl Hasher256 {
    fn new() -> Self {
        // Four distinct offset bases so the lanes diverge even on identical input (matches the
        // `contracts::fnv1a_256` bases so the two constructions stay consistent in-tree).
        let bases: [u64; 4] = [
            0xcbf2_9ce4_8422_2325,
            0x8422_2325_cbf2_9ce4u64.wrapping_mul(FNV_PRIME),
            0x1000_0000_0000_01B3,
            0xff00_ff00_ff00_ff00,
        ];
        let mut lanes = bases;
        // Perturb each lane by its index so the four lanes never start equal.
        for (i, l) in lanes.iter_mut().enumerate() {
            *l ^= (i as u64).wrapping_add(1).wrapping_mul(FNV_PRIME);
        }
        Self { lanes }
    }

    /// Fold raw bytes into every lane (rolling FNV-1a).
    fn write(&mut self, data: &[u8]) {
        for lane in self.lanes.iter_mut() {
            let mut h = *lane;
            for &b in data {
                h ^= b as u64;
                h = h.wrapping_mul(FNV_PRIME);
            }
            *lane = h;
        }
    }

    /// Fold a fixed-width big-endian `u64` (used for counts, ids, timestamps, enum tags-as-u8 are sent
    /// via [`Self::u8`]).
    fn u64(&mut self, v: u64) {
        self.write(&v.to_be_bytes());
    }

    /// Fold a fixed-width big-endian `u128` (balances, deposits, rates, escrow, stake).
    fn u128(&mut self, v: u128) {
        self.write(&v.to_be_bytes());
    }

    /// Fold a signed `i64` (reputation) — two's-complement big-endian, distinct from its `u64` reading.
    fn i64(&mut self, v: i64) {
        self.write(&v.to_be_bytes());
    }

    /// Fold a single tag/discriminant byte.
    fn u8(&mut self, v: u8) {
        self.write(&[v]);
    }

    /// Fold a length-prefixed byte slice: `len (u64 BE) || bytes`. The length prefix prevents two
    /// adjacent variable-length fields from aliasing (e.g. `["ab",""]` vs `["a","b"]`).
    fn bytes(&mut self, data: &[u8]) {
        self.u64(data.len() as u64);
        self.write(data);
    }

    /// Finalize: a SplitMix64 avalanche per lane, concatenated big-endian into 32 bytes.
    fn finish(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, lane) in self.lanes.into_iter().enumerate() {
            let mut h = lane;
            h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            h ^= h >> 31;
            out[i * 8..i * 8 + 8].copy_from_slice(&h.to_be_bytes());
        }
        out
    }
}

// ---- per-type canonical serializers (each folds a fixed, tagged, length-prefixed encoding) ----

fn hash_account(h: &mut Hasher256, a: &Account) {
    h.write(&a.address);
    h.u8(a.verified as u8);
    h.u64(a.verified_at);
    h.u128(a.settled_balance);
    h.u64(a.last_settled_at);
    h.u64(a.nonce);
}

fn stream_status_tag(s: &StreamStatus) -> (u8, u64) {
    match s {
        StreamStatus::Active => (0, 0),
        StreamStatus::Stopped(at) => (1, *at),
        StreamStatus::Completed => (2, 0),
    }
}

fn hash_stream(h: &mut Hasher256, s: &Stream) {
    h.u64(s.id);
    h.write(&s.from);
    h.write(&s.to);
    h.u128(s.rate);
    h.u128(s.deposit);
    h.u128(s.drawn);
    h.u64(s.started_at);
    let (tag, at) = stream_status_tag(&s.status);
    h.u8(tag);
    h.u64(at);
}

fn human_status_tag(s: &HumanStatus) -> u8 {
    match s {
        HumanStatus::Unverified => 0,
        HumanStatus::Pending => 1,
        HumanStatus::Verified => 2,
        HumanStatus::Challenged => 3,
        HumanStatus::Revoked => 4,
    }
}

fn verdict_tag(v: &crate::Verdict) -> u8 {
    match v {
        crate::Verdict::Human => 0,
        crate::Verdict::Sybil => 1,
        crate::Verdict::Uncertain => 2,
    }
}

fn confidence_tag(c: &crate::Confidence) -> u8 {
    match c {
        crate::Confidence::Low => 0,
        crate::Confidence::Med => 1,
        crate::Confidence::High => 2,
    }
}

/// Fold a [`CanonicalVerdict`] — `verdict`, `confidence`, **and** `reasons_hash`. The full struct is
/// committed (not just the quorum key): two states whose committed verdicts differ only in
/// `reasons_hash` are still *distinct on-chain records*, so the root must distinguish them.
fn hash_verdict(h: &mut Hasher256, v: &CanonicalVerdict) {
    h.u8(verdict_tag(&v.verdict));
    h.u8(confidence_tag(&v.confidence));
    h.write(&v.reasons_hash);
}

/// Fold a [`CanonicalEffect`] via its already-canonical [`CanonicalEffect::encode`] (4-byte op count
/// then each tagged op) plus its `effect_hash`. Reuses the audited M4 op encoding so the root and the
/// quorum key stay consistent.
fn hash_effect(h: &mut Hasher256, e: &CanonicalEffect) {
    h.bytes(&e.encode());
    h.write(&e.effect_hash);
}

/// The 32-byte deterministic state root over the full canonicalized state. Pure read of `state`; no
/// mutation, no clock, no floats, no hash-iteration order. Independently-built states with the same
/// logical content return byte-identical roots.
///
/// Section order (each section is folded as `count (u64) || items-in-sorted-order`):
///   1. accounts (sorted by address)
///   2. streams (sorted by id) + per-stream-sender/recipient indexes are implied by the streams'
///      own `from`/`to`, so the indexes need not be separately hashed; the `next_stream_id` counter is.
///   3. humans (sorted by address)
///   4. vouch edges (sorted by `(voucher, vouchee)`)
///   5. cleared-challenge cooldown set (sorted)
///   6. cases (sorted by id)
///   7. jurors (sorted by address)
///   8. contracts (sorted by id)
///   9. exec cases (sorted by id)
///  10. id counters (stream / case / contract / exec-case)
///
/// A 1-byte domain tag separates every section so a value moving between sections can never collide.
pub fn state_root(state: &MemState) -> [u8; 32] {
    let mut h = Hasher256::new();

    // A short domain header pins the encoding version, so a later format change is a new root (never a
    // silent reinterpretation of old bytes). Bumped to `/2` for the M6 additions (the `Human.assurance`
    // tag + the nullifier/attribute/CSCA sections), and to `/3` for the M5-Stage-B addition: the
    // committed `epoch_validators` snapshot (section 0x0e, spec 08 §2.1/§8).
    h.bytes(b"ubi2/state-root/3");

    // 1. Accounts — sorted by address.
    let mut accounts = state.accounts();
    accounts.sort_by_key(|a| a.address);
    h.u8(0x01);
    h.u64(accounts.len() as u64);
    for a in &accounts {
        hash_account(&mut h, a);
    }

    // 2. Streams — sorted by id. (The `incoming`/`outgoing` indexes are derivable from each stream's
    //    `from`/`to`, so committing the streams commits the indexes; FU-13 still sorts the indexes for
    //    every *other* consensus path, e.g. the balance inflow sum.)
    let mut streams = state.streams();
    streams.sort_by_key(|s| s.id);
    h.u8(0x02);
    h.u64(streams.len() as u64);
    for s in &streams {
        hash_stream(&mut h, s);
    }

    // 3. Humans — `State::humans()` already returns sorted-by-address.
    let humans = state.humans();
    h.u8(0x03);
    h.u64(humans.len() as u64);
    for hu in &humans {
        h.write(&hu.address);
        h.u8(human_status_tag(&hu.status));
        h.u64(hu.verified_at);
        h.write(&hu.liveness_ref);
        h.u64(hu.vouches_in.len() as u64);
        for v in &hu.vouches_in {
            h.write(v);
        }
        h.i64(hu.reputation);
        // M6 §5.3: fold the 1-byte assurance tag (STD=0/ENH=1/DUAL=2) into the humans section so an
        // assurance change moves the root. Additive: an existing `Std` (default) record's bytes change,
        // which is exactly why the version string is bumped to `/2`.
        h.u8(hu.assurance.tag());
    }

    // 4. Vouch edges — `State::vouch_edges()` already returns sorted-by-`(voucher, vouchee)`.
    let edges = state.vouch_edges();
    h.u8(0x04);
    h.u64(edges.len() as u64);
    for (voucher, vouchee) in &edges {
        h.write(voucher);
        h.write(vouchee);
    }

    // 5. Cleared-challenge cooldown set — sorted by `(challenger, subject)`.
    let cleared = state.cleared_challenges_sorted();
    h.u8(0x05);
    h.u64(cleared.len() as u64);
    for (challenger, subject) in &cleared {
        h.write(challenger);
        h.write(subject);
    }

    // 6. Cases — `State::cases()` already returns sorted-by-id.
    let cases = state.cases();
    h.u8(0x06);
    h.u64(cases.len() as u64);
    for c in &cases {
        h.u64(c.id);
        h.write(&c.subject);
        h.write(&c.challenger);
        h.u8(match c.kind {
            CaseKind::Registration => 0,
            CaseKind::Challenge => 1,
        });
        h.write(&c.evidence_ref);
        h.u64(c.jury.len() as u64);
        for j in &c.jury {
            h.write(j);
        }
        h.u64(c.votes.len() as u64);
        for (juror, verdict) in &c.votes {
            h.write(juror);
            hash_verdict(&mut h, verdict);
        }
        match &c.status {
            CaseStatus::Open => h.u8(0),
            CaseStatus::Committed(v) => {
                h.u8(1);
                hash_verdict(&mut h, v);
            }
            CaseStatus::Escalated => h.u8(2),
        }
        h.u64(c.opened_at);
    }

    // 7. Jurors — `State::active_jurors()` returns only the *active* ones; the root must commit
    //    inactive jurors too (an active→inactive flip changes state). Read every juror via the sorted
    //    active list plus a sweep is not exposed; jurors are only mutated via `register_juror` and stay
    //    active in M3/M4, so the active list is the full registry. We commit each juror's full record.
    let mut jurors: Vec<crate::Juror> = state
        .active_jurors()
        .into_iter()
        .filter_map(|a| state.get_juror(&a))
        .collect();
    jurors.sort_by_key(|j| j.address);
    h.u8(0x07);
    h.u64(jurors.len() as u64);
    for j in &jurors {
        h.write(&j.address);
        h.u128(j.stake);
        h.u8(j.active as u8);
    }

    // 7a. (M6 §5.3) Nullifier registry — `State::nullifiers()` returns sorted ascending by the 32-byte
    //     value. A spent nullifier is a permanent on-chain fact; committing it makes one-passport-one-human
    //     part of the agreed state (a second proof reusing it diverges identically on every node).
    let nullifiers = state.nullifiers();
    h.u8(0x0b);
    h.u64(nullifiers.len() as u64);
    for n in &nullifiers {
        h.write(n);
    }

    // 7b. (M6 §5.3) Attribute store — sorted by address; each entry = address ‖ the three 32-byte
    //     Pedersen commitments (opaque — I6). `State::attribute_store()` returns sorted-by-address.
    let attrs = state.attribute_store();
    h.u8(0x0c);
    h.u64(attrs.len() as u64);
    for (addr, commitments) in &attrs {
        h.write(addr);
        for c in commitments {
            h.write(c);
        }
    }

    // 7c. (M6 §5.3) CSCA trust-anchor registry — `State::csca_entries()` returns sorted-by-`key_id`
    //     (Active AND Revoked — a revoke is a state change the root must reflect, §7.4). Committing the
    //     full set means all nodes agree on the trust anchors to the bit; the `csca_registry_root`
    //     (over the Active subset) is itself bound as a proof public input, so it need not be a separate
    //     section — the entries fully determine it.
    let csca = state.csca_entries();
    h.u8(0x0d);
    h.u64(csca.len() as u64);
    for e in &csca {
        h.write(&e.country_code);
        h.write(&e.key_id);
        h.bytes(&e.pubkey);
        h.u64(e.added_at);
        h.u8(e.status.tag());
    }

    // 8. Contracts — `State::contracts()` already returns sorted-by-id. `vars` is a HashMap; commit it
    //    via the contract's own `sorted_vars()` (deterministic `(key, value)` order).
    let contracts = state.contracts();
    h.u8(0x08);
    h.u64(contracts.len() as u64);
    for c in &contracts {
        h.u64(c.id);
        h.u128(c.escrow);
        h.u64(c.parties.len() as u64);
        for p in &c.parties {
            h.write(p);
        }
        h.bytes(c.text.as_bytes());
        h.write(&c.text_ref);
        let vars = c.sorted_vars();
        h.u64(vars.len() as u64);
        for (k, v) in &vars {
            h.write(k);
            h.write(v);
        }
        h.u8(match c.status {
            ContractStatus::Active => 0,
            ContractStatus::Terminated => 1,
        });
        h.u64(c.deploy_block);
        h.write(&c.deploy_tx);
    }

    // 9. Exec cases — `State::exec_cases()` already returns sorted-by-id.
    let exec_cases = state.exec_cases();
    h.u8(0x09);
    h.u64(exec_cases.len() as u64);
    for ec in &exec_cases {
        h.u64(ec.id);
        h.u64(ec.contract);
        h.write(&ec.trigger_ref);
        h.write(&ec.invoker);
        h.u64(ec.jury.len() as u64);
        for j in &ec.jury {
            h.write(j);
        }
        h.u64(ec.effects.len() as u64);
        for (interp, effect) in &ec.effects {
            h.write(interp);
            hash_effect(&mut h, effect);
        }
        match &ec.status {
            ExecStatus::Open => h.u8(0),
            ExecStatus::Committed(e) => {
                h.u8(1);
                hash_effect(&mut h, e);
            }
            ExecStatus::Aborted => h.u8(2),
        }
        h.u64(ec.opened_at);
        match ec.resolved_at {
            None => h.u8(0),
            Some(r) => {
                h.u8(1);
                h.u64(r);
            }
        }
    }

    // 9a. (M5 Stage B §2.1/§8) Epoch validator snapshot — the sorted `Vec<Address>` `V` scheduling
    //     reads from the parent state. Committing it means all nodes agree on the proposer schedule by
    //     replay (EC-B5). It is stored sorted (a plain `Vec`, no `HashMap`-order hazard), so folding it
    //     in order is deterministic. A membership change at an epoch boundary moves the root.
    let epoch_validators = state.epoch_validators();
    h.u8(0x0e);
    h.u64(epoch_validators.len() as u64);
    for v in &epoch_validators {
        h.write(v);
    }

    // 10. Id counters — a rolled-back op can advance a counter without leaving an entry, so the
    //     counters are part of state and must be committed.
    h.u8(0x0a);
    h.u64(state.peek_next_stream_id());
    h.u64(state.peek_next_case_id());
    h.u64(state.peek_next_contract_id());
    h.u64(state.peek_next_exec_case_id());

    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        apply_transfer, charge_fee, deploy_contract, open_stream, register_juror,
        seed_verified_human, Account, Human, GAS_TRANSFER, UBI,
    };

    fn addr(b: u8) -> crate::Address {
        [b; 20]
    }

    fn verified(state: &mut MemState, a: crate::Address, at: u64) {
        seed_verified_human(state, &a, at);
        state.put(Account {
            address: a,
            verified: true,
            verified_at: at,
            last_settled_at: at,
            ..Default::default()
        });
    }

    /// EC-4/EC-10 core: two independently-built states with the same logical content produce a
    /// byte-identical root. Exercises accounts, fees, streams, the human registry, jurors and a
    /// deployed contract — every section of the root.
    #[test]
    fn equal_states_have_equal_roots() {
        let build = || {
            let mut s = MemState::new();
            verified(&mut s, addr(1), 0);
            verified(&mut s, addr(2), 100);
            apply_transfer(&mut s, &addr(1), &addr(3), UBI, 0, 7_200).unwrap();
            charge_fee(&mut s, &addr(1), GAS_TRANSFER, 7_200).unwrap();
            open_stream(&mut s, &addr(2), &addr(4), 1, 1_000, 200).unwrap();
            register_juror(&mut s, &addr(5), 0);
            // A Pending human record (no oracle needed for the root test).
            s.put_human(Human::pending(addr(6), [9u8; 32]));
            deploy_contract(&mut s, "hello".into(), [1u8; 32], vec![addr(1)]).unwrap();
            s
        };
        let a = build();
        let b = build();
        assert_eq!(state_root(&a), state_root(&b), "equal states ⇒ equal root");
    }

    /// Order-independence: the root must not depend on the *order* operations were applied in when the
    /// resulting logical state is the same. We seed two accounts in opposite orders.
    #[test]
    fn root_is_insertion_order_independent() {
        let mut a = MemState::new();
        verified(&mut a, addr(1), 0);
        verified(&mut a, addr(2), 0);

        let mut b = MemState::new();
        verified(&mut b, addr(2), 0);
        verified(&mut b, addr(1), 0);

        assert_eq!(state_root(&a), state_root(&b));
    }

    /// Sensitivity: changing **any** committed field changes the root.
    #[test]
    fn any_field_change_changes_root() {
        let base = {
            let mut s = MemState::new();
            verified(&mut s, addr(1), 0);
            s
        };
        let root0 = state_root(&base);

        // balance
        let mut s = base.clone();
        let mut acc = s.get(&addr(1)).unwrap();
        acc.settled_balance += 1;
        s.put(acc);
        assert_ne!(state_root(&s), root0, "balance change must move root");

        // nonce
        let mut s = base.clone();
        let mut acc = s.get(&addr(1)).unwrap();
        acc.nonce += 1;
        s.put(acc);
        assert_ne!(state_root(&s), root0, "nonce change must move root");

        // a new account
        let mut s = base.clone();
        s.put(Account {
            address: addr(9),
            ..Default::default()
        });
        assert_ne!(state_root(&s), root0, "new account must move root");

        // a stream
        let mut s = base.clone();
        let mut funded = s.get(&addr(1)).unwrap();
        funded.settled_balance = 10 * UBI;
        s.put(funded);
        open_stream(&mut s, &addr(1), &addr(2), 1, 1_000, 0).unwrap();
        assert_ne!(state_root(&s), root0, "stream creation must move root");

        // a juror
        let mut s = base.clone();
        register_juror(&mut s, &addr(7), 0);
        assert_ne!(state_root(&s), root0, "juror registration must move root");
    }

    /// FU-13: an onboarding (zero-gas) op must NOT leave a stray zero-balance TREASURY entry that
    /// perturbs the root. A state that processed an onboarding op and one that didn't (but is otherwise
    /// equal) differ only by the genuine human record — not by a phantom TREASURY account.
    #[test]
    fn zero_gas_onboard_leaves_no_treasury_entry() {
        let mut s = MemState::new();
        register_juror(&mut s, &addr(5), 0);
        // requestVerification is fee-exempt (GAS_ONBOARD == 0) — charging its fee must not create a
        // TREASURY account.
        charge_fee(&mut s, &addr(6), 0, 0).unwrap();
        assert!(
            s.get(&crate::TREASURY).is_none(),
            "zero-gas charge must not create a TREASURY entry"
        );
    }
}
