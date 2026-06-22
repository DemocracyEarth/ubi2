# Security gate — M3 AI Proof-of-Humanity (board M3-T8)

- **Branch/commit:** `m3-proof-of-humanity` @ `bd669d2`
- **Gate:** Security (defender / red-team, this project only)
- **Verdict:** **FAIL** — one open **HIGH** finding (A) on the M3 diff.
- **Devnet used:** `127.0.0.1:38545` (security port), killed after the run.
- **PoCs:** `crates/runtime/tests/sec_m3_poc.rs` (5 tests, all green) + live RPC txs below.

PASS only if no open High/Critical remains on the M3 diff. Finding A is High and open, so the
gate is **FAIL**. Findings B–D are follow-ups; remediating A (and ideally B) clears the gate.

---

## Findings (ranked)

### A — HIGH — Unauthenticated, uncapped challenge-spam blocks any human indefinitely (DoS / griefing)

**Where:** `crates/runtime/src/lifecycle.rs::challenge` (ignores `_challenger`, no cost, no cap),
`has_pending_or_upheld_challenge` (an `Open` challenge blocks `finalize_registration`); reachable
from `crates/rpc/src/lib.rs` via `eth_sendRawTransaction` → `HumanityHub` → `PendingKind::Challenge`.

**Issue:** `challenge(subject, evidenceRef)` is callable by **any** address. The challenger is never
authenticated (`_challenger` is unused), there is no stake/bond, no per-subject cooldown, and no cap
on concurrent or sequential challenges. Each call opens a fresh `Open` Challenge case, and an `Open`
challenge case makes `finalize_registration` return `ChallengePending`. So an attacker who pays only
gas can:
- keep a legitimate `Pending` applicant from **ever** finalizing (and therefore from ever streaming
  UBI) by re-filing a challenge each block — even after the jury clears each one `Human`;
- keep any already-`Verified` human perpetually flipped to `Challenged` (see Finding B).

This breaks acceptance criterion 1 ("a clean challenge window → Verified → streams") under a hostile
peer and is an availability break on the core lifecycle, hence HIGH (it denies a legitimate human
their UBI indefinitely for the cost of gas).

**PoC (runtime):** `sec_m3_poc.rs::poc_a_challenge_spam_blocks_finalize_indefinitely` — a non-verified,
non-juror `0x6363…` re-files 50 challenges against a legitimate victim that cleared the window; every
`finalize_registration` returns `ChallengePending`; the victim never verifies. The loop is unbounded.

**PoC (live, port 38545):** a random attacker key (Anvil acct #9, `0xa0Ee7A14…9720` — not a juror,
not verified) signed one `challenge(devAccount, 0x11..11)` EIP-155 tx to `0x…5048`. It was accepted
and mined; `ubi_getHuman(dev)` flipped from `Verified` to `Challenged`, and `ubi_getPendingCases`
shows the attacker-opened case. No authorization was required.

**Remediation:**
1. Gate who may challenge and at what cost: require the challenger to be `Verified`, and/or require a
   challenge **bond** that is slashed if the jury returns `Human` (refunded on upheld `Sybil`). This
   makes spam costly and aligns incentives.
2. Cap outstanding challenges per subject (e.g. one `Open` challenge at a time; reject a second while
   one is `Open`), and add a per-`(challenger, subject)` cooldown.
3. Do not let an `Escalated` *or repeatedly re-filed* challenge stall finalization forever: after a
   challenge resolves `Human` (or escalates to human appeal), the subject should be finalizable;
   re-challenge should require new evidence + bond, not be free.

---

### B — MEDIUM — Escalated/!-resolved challenge leaves a human stuck `Challenged` (authority loss)

**Where:** `crates/runtime/src/lifecycle.rs::submit_verdict` — a `Challenged` human is restored to
`Verified` **only** on a committed `Human` verdict; on `Escalated` (split/`Uncertain`) nothing
restores it. There is no human-appeal / un-challenge transition in M3.

**Issue:** A single cheap challenge flips a `Verified` human to `Challenged`. If the jury splits or
returns `Uncertain`, the case `Escalates` and the human is **stuck `Challenged` with no recovery
path**. Emission continues (correct — I4, innocent until proven), but the human loses `Verified`
authority: e.g. `vouch` requires `status == Verified`, so a stuck-`Challenged` founder can no longer
vouch. An attacker can permanently strip vouching authority from any verified human for one tx.

**PoC:** `sec_m3_poc.rs::poc_b_escalated_challenge_leaves_human_stuck_challenged` — challenge →
`Challenged`, jury splits → `Escalated`, victim remains `Challenged`, and a subsequent `vouch` from
the victim fails `VoucherNotVerified`.

**Remediation:** define the escalation resolution path (spec says "escalate → extend window, enlarge
jury, or human appeal"). At minimum, an `Escalated` challenge against a previously-`Verified` human
should restore it to `Verified` (fail-safe back to the prior good state) unless/until a quorum upholds
`Sybil`, mirroring "innocent until proven." Treat `Challenged` as still-`Verified` for the vouch
authority check, or add an explicit un-challenge transition.

---

### C — MEDIUM — Fixed, non-rotatable 3-juror quorum; 2-of-3 collusion controls all verdicts

**Where:** `crates/node/src/main.rs` (three hard-coded Anvil juror keys, register-only), `lifecycle`
trusts the **self-reported** verdict byte in each `submitVerdict` tx and never re-derives it.

**Issue:** With `JURY_SIZE = 3` and exactly three registered jurors, every case's jury is the whole
set; `QUORUM = 2`. The runtime correctly resists a hostile **minority** (1 of 3 cannot flip — verified
in `control_malicious_minority_juror_cannot_flip_is_blocked`), but a colluding **majority** (any 2 of
3) fully controls every outcome: it can revoke any human or whitewash any sybil. There is no juror
removal/rotation/slashing and no on-chain check that a juror's submitted verdict matches what its
oracle would produce — jurors are trusted to self-report. The seeded juror keys are the **public**
Anvil keys, so on the devnet the quorum integrity is nominal.

**PoC (live, port 38545):** jurors #1 and #2 (Anvil keys, the seeded majority) each signed
`submitVerdict(case 0, Sybil, High)`; the dev founder went `Challenged → Revoked`, `verified_at`
cleared. Two keys revoked the genesis human.

**Assessment:** this is the intended M3 trust model (single-node devnet, register-only jurors, staking
deferred to M5), so it is MEDIUM rather than HIGH — but it must be recorded: (a) the seeded juror keys
are public and must never be reused with value; (b) M3 has no juror rotation or removal path, so two
leaked/colluding keys are a permanent capture; (c) randomized per-case juror selection only matters
once the juror pool exceeds `JURY_SIZE` — today it does not, so `select_jury` is a no-op.
**Remediation (M5 track):** juror staking + slashing, a larger active pool than `JURY_SIZE` so
selection is actually random, and a rotation/removal path. For M3, document the trust assumption and
never reuse the seeded keys.

---

### D — LOW — Criterion 6 (AI sybil-cluster auto-challenge) is not wired into the live node path

**Where:** `crates/rpc/src/lib.rs::produce_block` — `analyze_sybil` / `graph_view()` are never called;
the only sybil-scan invocation in the tree is inside the *manual* test
`m3_humanity.rs::sybil_cluster_scan_auto_challenges`, which calls `oracle.analyze_sybil` and then
hand-files a `challenge`.

**Issue:** The spec's defensive auto-challenge ("AI sybil scan auto-files a challenge on flagged
vouch-clusters") is not active on the node. A vouch farm that secures enough vouches and clears the
window will finalize unless a human happens to challenge it; the system's own structural defense
against sybil clusters never fires. This is a missing defense-in-depth layer, not a direct exploit
(the jury path still catches a *challenged* sybil), so LOW from a pure-security view — but it is a
functional gap against acceptance criterion 6 that QA should also flag.

**Remediation:** in `produce_block` (or the auto-finalize sweep), run `analyze_sybil` over the
deterministic `graph_view()` for each `Pending` subject and auto-file a `Challenge` when it returns
`Sybil`, exactly as the test stages it manually. Keep it deterministic (sorted graph, MockOracle in
CI).

---

## Controls verified to HOLD (no action needed)

- **Juror authorization:** `submit_verdict` enforces `case.jury.contains(juror)`; a non-juror is
  rejected `NotOnJury`, a double-vote `AlreadyVoted`
  (`control_non_juror_cannot_vote_is_blocked`, runtime test `submit_verdict_authorization`).
- **Hostile minority:** 1 malicious juror of 3 cannot flip a 2-vote quorum
  (`control_malicious_minority_juror_cannot_flip_is_blocked`).
- **Vouch constraints:** only `Verified` vouchers; `VOUCH_CAPACITY` cap across accounts; no self-vouch;
  no duplicate edge (`vouch_constraints_enforced`, `vouch_capacity_enforced`,
  `control_vouch_caps_hold_is_blocked`). No vouch into multiple accounts beyond capacity.
- **Replay / signature:** `ingest_raw_tx` requires EIP-155 chain-id binding (rejects pre-155 and
  wrong-chain txs), recovers the signer from the secp256k1 signature, and enforces a strict per-sender
  nonce at submit and at apply (`consume_nonce`). No verdict/challenge/vouch replay across chains or
  within the chain.
- **Privacy (I6):** `ubi_getHuman`/`ubi_getCase`/`ubi_getJurors` expose **only** commitments
  (`liveness_ref`, `evidence_ref`), bucketed canonical verdicts, and reason *hashes* — never raw
  challenge/response bytes, biometric, or rationale prose. Confirmed live on port 38545. The on-chain
  `Case`/`Human` types structurally cannot hold raw evidence.
- **Prompt-injection (oracle):** `crates/oracle/src/prompt.rs` fences all attacker-controlled evidence
  in an UNTRUSTED data block, defangs forged open/close markers (`frame_evidence` `.replace`), and the
  output is grammar-constrained to a closed `{verdict,confidence,reasons}` enum schema
  (`additionalProperties:false`); the system prompt instructs "lean Sybil on manipulation, never
  Human." I verified the defang is robust against nested/overlapping marker injection (the replacement
  text contains no `<`, so it cannot reconstitute a marker in one pass). An injection can at most push
  *which enum value* is chosen, never break the effect shape or exfiltrate (no tools/network/state on
  the oracle). The live path is fixture-gated; the shipping prompt construction is sound.
- **Determinism / quorum integrity (I1):** `tally` is order-independent and escalates on
  split/`Uncertain` (never coin-flips); `select_jury` sorts+dedups then seeded-shuffles; oracle errors
  map to `Uncertain/Low` (fail-closed). `reasons_hash` is excluded from quorum equality so prose can't
  split a quorum.
- **Emission gating (I2):** balance accrues iff `Account.verified`; `Pending`/`Revoked` accrue zero
  (`pending_account_does_not_stream`, `emission_gates_on_verified_and_revoke_stops`); `revoke` clears
  the cache to the base unit. No integer/fixed-point issue found in the gating path.
- **Hygiene:** no real secrets in code or env; the only "private key" present is the public Anvil
  account #0, correctly labeled non-secret and used only as a demo fallback signer
  (`apps/wallet/app/config.ts`). `ANTHROPIC_API_KEY` is env-only, scrubbed from error strings, and
  redacted in `Debug`. No `.env` committed.

---

## Gate decision

**FAIL.** Finding A (HIGH) is open: an unauthenticated, free, uncapped challenge can deny any human
their verification/UBI indefinitely (live-confirmed). Remediate A (challenger gating + bond +
per-subject cap/cooldown, and don't let an open/re-filed challenge stall finalization forever);
strongly recommend fixing B (stuck-`Challenged` recovery) in the same change. C is the documented M3
juror trust model (M5 hardening); D is a defense-in-depth/criterion-6 gap for QA + a later wire-up.
Re-run this gate after the A/B fix.
