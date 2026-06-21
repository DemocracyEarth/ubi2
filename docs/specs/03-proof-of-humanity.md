# 03 — Milestone 3: AI Proof-of-Humanity (social vouching + AI jury)

**Status:** spec (architect, cycle 3).
**Goal:** make `verified` **earned**, not a genesis flag. A new account becomes a verified unique human
by (1) passing an **AI-graded liveness** check (presence), (2) collecting **vouches** from existing
verified humans (uniqueness, web-of-trust), and (3) surviving a **challenge window** in which suspected
duplicates/sybils are adjudicated by an **AI-jury quorum** that reaches a deterministic verdict. Only
`Verified` humans accrue the 1 UBI/hour stream. This is also the network's first **multi-node consensus**
(the verifier quorum) and the reusable substrate for M4 prompt contracts.

Decisions made with product (Santiago): anchor uniqueness on **social vouching + AI** (Proof-of-Humanity
heritage; no hardware, privacy-preserving), and build the **full uniqueness system** in this milestone
(vouch graph + AI sybil analysis + AI-jury disputes), not a thin slice.

## The two axes (don't conflate them)
- **Presence** — "a real human is acting here, now." AI is genuinely useful: generate novel, un-pre-solvable
  challenges and grade them. *Necessary, not sufficient* — generative AI can imitate a human.
- **Uniqueness** — "this is one human, counted once." The crux. Solved socially (vouching graph) +
  AI sybil-cluster analysis + AI-jury disputes. No single AI challenge proves uniqueness.

## On-chain state (`crates/runtime`)
```
HumanStatus = Unverified | Pending | Verified | Challenged | Revoked
Human {
  address, status,
  verified_at: u64,              // when Verified (drives emission; replaces M1 genesis flag)
  liveness_ref: Hash,            // commitment to the off-chain liveness evidence (no PII on-chain)
  vouches_in:  [Address],        // distinct Verified vouchers
  reputation:  i64,              // voucher reputation; slashed for vouching a proven sybil
}
Vouch { voucher, vouchee, at }   // voucher must be Verified; capacity-limited; no self/duplicate vouch
Case  {                          // a verification or a challenge under adjudication
  id, subject: Address, kind: Registration | Challenge,
  evidence_ref: Hash,            // content-addressed inputs all jurors see identically
  jury: [Address],              // quorum selected for this case (randomized from the juror registry)
  votes: Map<juror, CanonicalVerdict>,
  status: Open | Committed(verdict) | Escalated,
}
Juror { address, stake, active }
```
Constants (tunable, in spec): `MIN_VOUCHES = V`, `VOUCH_CAPACITY = K`, `CHALLENGE_WINDOW`,
`JURY_SIZE = N`, `QUORUM = ⌈2N/3⌉`. State additions live behind the existing `State` trait (swappable).

## Verdicts & the AI Oracle seam (`crates/runtime` trait, filled by `ai-engineer`)
The committed value is a **canonical verdict**, never prose:
```
CanonicalVerdict { verdict: Human | Sybil | Uncertain, confidence_bucket: Low|Med|High, reasons_hash: Hash }
trait HumanityOracle {                       // off-chain; each juror node runs it, signs the result
  fn grade_liveness(&self, challenge: &Bytes, response: &Bytes) -> CanonicalVerdict;
  fn analyze_sybil(&self, graph: &GraphView, subject: &Address) -> CanonicalVerdict;  // flags clusters
  fn adjudicate(&self, evidence: &Bytes) -> CanonicalVerdict;                          // dispute jury
}
```
- **Determinism (I1):** pinned model + seed + **temperature 0** + canonical structured output. The chain
  commits a case only when **≥ QUORUM jurors produce the *same* `CanonicalVerdict`** (verdict + confidence
  bucket must match; `reasons_hash` is informational). Disagreement / `Uncertain` ⇒ **Escalate**
  (extend window, enlarge jury, or human appeal) — never a coin-flip (I4: fail closed).
- **Testable offline (I5):** ship a `MockOracle` returning scripted verdicts so the entire on-chain
  lifecycle + tally + tests run in CI **without live model calls**. The live node wires a Claude-backed
  oracle (latest model per the project's `claude-api` guidance; pinned + versioned).

## Lifecycle (deterministic state machine)
```
requestVerification(subject, liveness_ref)            → Pending, opens a Registration Case
  └ jury grades liveness (quorum) ─ pass → continue ─ fail → reject
gather vouches (≥ MIN_VOUCHES distinct Verified)      → eligibility
challenge window opens (CHALLENGE_WINDOW blocks)
  ├ anyone: challenge(subject, evidence_ref)          → Challenged, opens a Challenge Case
  └ AI sybil scan auto-files a challenge on flagged vouch-clusters
resolve case via AI-jury quorum:
  Sybil  (≥QUORUM) → reject/Revoke + slash vouchers' reputation
  Human  (≥QUORUM) → uphold
  Uncertain/split  → Escalate
window clears with no upheld challenge + liveness passed + enough vouches → Verified → UBI streams
later: periodic re-liveness; a Verified human may be re-challenged → re-adjudicated; Revoke stops emission
```
Juror selection is randomized per case (VRF-style from chain entropy) to resist collusion; jurors submit
**signed** verdicts as transactions; the runtime tallies deterministically.

## RPC / interfaces
- Write (EIP-155 txs, MetaMask-signable, via a `HumanityHub` system address like StreamHub):
  `requestVerification`, `vouch(address)`, `challenge(address, evidenceRef)`, `submitVerdict(caseId, verdict)`.
- Read (`ubi_*`): `getHuman(address)`, `getCase(id)`, `getVouches(address)`, `getJurors()`,
  `getPendingCases()`. `eth_getBalance` already gates on emission, which now keys off `Verified`.
- Wallet: an **apply / verify** flow (do the liveness challenge, watch vouches accrue, see status),
  a **vouch** action, a **challenge** action, and a juror/verdict view. (Stream + balance UIs unchanged.)

## Invariants this milestone must uphold
- **I1** deterministic quorum verdicts (above). First real multi-node consensus.
- **I2** emission still a pure integer function of `(state, now)`; `Verified`/`verified_at` are the only new
  gating inputs — reproducible.
- **I4** safe degradation: deny/escalate on uncertainty; never auto-grant. Revocation requires a quorum.
- **I6** least authority / privacy: **no PII or biometric on-chain** — only commitments (`liveness_ref`,
  `evidence_ref`), canonical verdicts, and reason hashes.

## Acceptance criteria (map 1:1 to tests; AI parts use the MockOracle)
1. A new account goes `Unverified → Pending → Verified` only after liveness-pass + ≥`MIN_VOUCHES` +
   a clean challenge window, and **only then** does its balance start streaming.
2. A duplicate/sybil is caught: a challenge → AI-jury quorum returns `Sybil` by ≥`QUORUM` → subject
   `Revoked`/rejected, UBI not granted (or stopped), vouchers' reputation slashed.
3. **Quorum determinism (I1):** with fixed evidence + `MockOracle`, all honest jurors produce the same
   `CanonicalVerdict`; ≥`QUORUM` commits; a split deterministically `Escalate`s — reproducible across two nodes.
4. Vouch constraints: only `Verified` vouchers; capacity (`VOUCH_CAPACITY`) enforced; no self/duplicate vouch.
5. `verified` gating: emission accrues iff `Verified`; `Revoke` stops it to the base unit. The genesis dev
   account is migrated to `Verified` (devnet continuity).
6. AI sybil-cluster detection: a synthetic vouch farm (improbable cluster) is flagged and auto-challenged.
7. Privacy (I6): no PII/biometric on-chain; only commitments + canonical verdicts + reason hashes.
8. Wallet: apply→liveness→vouch→status flow works against the devnet; a juror can submit a verdict and a
   user can challenge another account.

## Scope cuts (deferred, recorded)
Real multimodal CV liveness (M3 ships an AI-graded interactive challenge behind the same trait; richer
video/voice liveness later); production VRF juror selection (M3 may use a simpler deterministic-random
seed); juror staking economics depth; cross-account biometric matching (the "Biometric + ZK" option stays
a future alternative/augmentation). Periodic re-verification cadence tuning is M3-late / M5.

## Open questions for M3-T1 finalization
- `MIN_VOUCHES`, `VOUCH_CAPACITY`, `JURY_SIZE`, `CHALLENGE_WINDOW` starting values.
- Whether jurors stake in M3 or just register (recommend: register-only for M3, stake in M5).
- Bootstrapping the seed set of Verified humans (genesis dev account + a small founder set vouch outward).
