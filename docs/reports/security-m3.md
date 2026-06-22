# Security gate — M3 AI Proof-of-Humanity (board M3-T8)

- **Branch/commit:** `m3-proof-of-humanity` @ `68013b5` (re-gate; original gate at `bd669d2`)
- **Gate:** Security (defender / red-team, this project only)
- **Verdict (RE-GATE 2026-06-22):** **PASS** — Finding A (HIGH) **CLOSED**, Finding B (MEDIUM)
  **CLOSED**. No open High/Critical remains on the M3 diff.
- **Devnet used:** `127.0.0.1:38545` (security port), killed after the run (port confirmed closed).
- **PoCs:** `crates/runtime/tests/sec_m3_poc.rs` (10 tests, all green) + fresh live RPC attacks below.
- **Workspace:** `cargo test --workspace` = **157 passed, 0 failed**; `cargo fmt --all --check` clean;
  `cargo clippy --workspace --all-targets -- -D warnings` clean.

PASS only if no open High/Critical remains on the M3 diff. After the protocol-engineer's fix the
HIGH (A) and the MEDIUM (B) are both closed and independently re-verified (in-process PoCs + live
devnet attacks). The gate is now **PASS**. C remains the documented M3 juror trust model (M5
hardening track); D is now **wired live** (`sweep_sybil_scan` in `produce_block`).

---

## RE-GATE 2026-06-22 — outcome (the gating section; the original findings are preserved below)

### Finding A (HIGH) — CLOSED. Challenge-spam DoS is fixed (authenticated + capped + cooled-down).

The fix lives in `crates/runtime/src/lifecycle.rs::challenge_inner` (three fail-closed, deterministic
rules) + the new `FALSE_CHALLENGE_SLASH` and `(challenger, subject)` cooldown set. Re-verified three
ways:

1. **In-process PoC** (`sec_m3_poc.rs::poc_a_challenge_spam_blocks_finalize_indefinitely`, green):
   the unverified attacker is rejected `ChallengerNotVerified`; a single Verified challenger's
   50-round refile loop now accepts **exactly 1** challenge (the rest are `ChallengeOnCooldown`); the
   legit victim then **finalizes and streams**. The unbounded DoS loop is dead.
2. **Live devnet (:38545), fresh attacks** — all three rules fire at block apply time and the
   offending tx is **dropped with no case opened / no receipt** (node WARN log captured each time):
   - unverified attacker `0x11Ea…0150` (Anvil #9, not a juror/human) → tx dropped
     `challenger is not a verified human`; the targeted Verified human stayed `Verified`, zero
     pending cases, no receipt. (A.1)
   - a Verified challenger (the dev founder) opened **one** Challenge case against a Pending applicant;
     a second concurrent challenge → dropped `subject already has an open challenge`, still exactly one
     Open case. (A.2)
   - the jury cleared the case `Human` (2-of-3 quorum); a re-file by the same challenger → dropped
     `challenger already cleared a challenge on this subject`, zero Open challenges remain. (A.3)
3. **False-challenge incentive** — a cleared-`Human` challenge slashes the challenger's reputation by
   `FALSE_CHALLENGE_SLASH = 50` (integer, deterministic). Reputation is display-only in M3 (it gates no
   lifecycle decision), so the self-slash is a pure disincentive with no exploitable side effect.

A committed-`Human` challenge never blocked `finalize_registration` (`has_pending_or_upheld_challenge`
returns false for `Committed(Human)`); only the perpetual **re-filing** did, and that is now bounded to
one attempt per `(challenger, subject)`. A genuine sybil is still revoked by a `Sybil` quorum
(`genuine_sybil_quorum_still_revokes`, green) — the hardening blocks only spam.

### Finding B (MEDIUM) — CLOSED. Escalation no longer strips an established human.

`submit_verdict` now fail-safe restores a `Challenged` (always-previously-`Verified`) subject to
`Verified` on an `Escalated` outcome of a `Challenge` case, re-syncing the emission cache with the
original `verified_at`. Re-verified:

- **In-process PoC** (`poc_b_…`, green): challenge → `Challenged`; jury splits → `Escalated`; victim is
  restored to `Verified` and a subsequent `vouch` from the victim **succeeds** (vouch authority kept).
- **Live devnet** — a Verified human under a split jury (`Human/High`, `Sybil/High`, `Uncertain/Low`)
  → case `Escalated`, `ubi_getHuman` flips back to `Verified`, and `eth_getBalance` keeps climbing
  (emission preserved). Only a `Sybil` quorum strips an established human now.

The restore is correctly guarded (`if kind == Challenge && h.status == Challenged`): `Challenged` only
ever arises from challenging a previously-`Verified` human, and a Pending applicant under challenge
stays `Pending` — so escalation can never auto-promote a Pending applicant (I4 preserved).

### Finding D (LOW) — CLOSED (now wired live). AC6 sybil auto-challenge fires in `produce_block`.

`crates/rpc/src/lib.rs::sweep_sybil_scan` runs each block (before `sweep_finalize`): for each
address-sorted `Pending` subject it runs `oracle.analyze_sybil` over `graph_view()` and auto-files a
`system_challenge` (reserved `HUMANITY_HUB` opener; verified-challenger gate waived; same one-open /
cooldown caps; keccak `(subject, block_hash)` evidence commitment — I6-safe). Confirmed by
`m3_qa::ac6_rpc_sybil_cluster_auto_challenge_and_revoke` (green): the node opens the case itself
(visible in `ubi_getPendingCases`) and the flagged cluster is revoked, never streaming UBI.

### Regression / new-issue scan — no new High/Critical introduced.

- **Determinism (I1/I2/I4/I6) preserved.** All lifecycle ops stay pure functions of `(state)`:
  integer reputation slashes (no floats); the cooldown set uses membership-only `contains`/`insert`
  (no iteration on any output path); `clear_vouch_edges` uses order-independent `retain`;
  `liveness_passed`/`registration_opened_at` `rfind` over the id-sorted `cases()`; the sybil sweep
  scans address-sorted `Pending` over the sorted `graph_view`. On-chain types still hold only
  commitments. The two PoC suites and the 23-test reliability suite (property tests, 10k–50k iters)
  re-confirm two-node byte-agreement.
- **`clear_vouch_edges` does not corrupt unrelated edges** — removing subject `S` drops only edges
  touching `S`; a founder's `(F → A)` vouch to a *different* applicant `A` survives (verified by
  semantic check + `reregister_allows_prior_voucher_to_revouch`, green).
- **Cooldown is not a sybil-immunity weapon (LOW residual, accepted).** The cooldown is per-
  `(challenger, subject)`; a different verified human (or the system scan) can still challenge a real
  sybil, so no permanent shield exists. The one exception — if a jury is *fooled* into clearing a
  system-opened challenge `Human`, the node will not auto-re-file that subject — depends on the jury
  being compromised, which is **outside M3's honest-majority threat model** (documented Finding C). A
  human can always still challenge it. Defense-in-depth limitation, not a regression. Track for M5
  (juror staking/rotation).
- **Reputation slash is not a cross-account grief.** The slash hits only the *challenger* who filed
  (never the subject or a third party), and reputation gates nothing in M3 — no exploitable effect.
- **Cooldown-set growth is bounded** by jury throughput (each entry requires a Verified challenger +
  a full quorum-committed `Human`), so it is not a memory-exhaustion DoS.

### Gate decision (re-gate): **PASS.**

No open High/Critical on the M3 diff. A and B are closed and independently re-verified (in-process +
live). D is wired live. C remains the documented, accepted M3 juror trust model (M5 hardening). The
`orchestrator` may mark M3-T8 Done.

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

## Gate decision (original — superseded by the RE-GATE 2026-06-22 section at the top)

**FAIL.** Finding A (HIGH) is open: an unauthenticated, free, uncapped challenge can deny any human
their verification/UBI indefinitely (live-confirmed). Remediate A (challenger gating + bond +
per-subject cap/cooldown, and don't let an open/re-filed challenge stall finalization forever);
strongly recommend fixing B (stuck-`Challenged` recovery) in the same change. C is the documented M3
juror trust model (M5 hardening); D is a defense-in-depth/criterion-6 gap for QA + a later wire-up.
Re-run this gate after the A/B fix.

> **UPDATE (re-gate `68013b5`, 2026-06-22): RESOLVED → PASS.** The protocol-engineer applied the
> challenger gating + one-open cap + per-`(challenger, subject)` cooldown + false-challenge slash (A)
> and the escalation fail-safe restore (B). Both are independently re-verified (10 in-process PoCs +
> fresh live `:38545` attacks); D is now wired into `produce_block`. Workspace 157/157 green, fmt +
> clippy clean. No open High/Critical remains. See the **RE-GATE** section at the top of this file.
