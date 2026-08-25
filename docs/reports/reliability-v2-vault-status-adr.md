# Reliability gate — V2 production vault and private status refresh ADR

- **Gate:** deterministic/reliability review before implementation
- **Reviewer:** reliability-engineer
- **Date:** 2026-08-25
- **Scope:** witness derivation, authenticated resolution, ordering/rollback, CAS, crash recovery and migration
- **Verdict:** **PASS — approved for implementation only**

No Critical/High or consistency blocker remains. This ADR changes no consensus/balance state; balance
reproducibility is not applicable.

## Properties verified

- Missing packed chunks are all ones, default subtrees are domain-separated, changed nodes combine in a unique
  bottom-up order and exactly 24 siblings/directions derive from the private slot.
- Snapshot bytes, resolver/reconciler signatures, issuer-active/accepted state, root, watermark and publication
  time bind to one short-lived finalized observation.
- A higher snapshot id permits equal publication time (same-block publication); equal id is an idempotent no-op
  only for exact root/time/watermark; lower id/time and same-id divergence reject.
- Whole-vault JCS CAS covers key slots and ciphertext. Every execution path terminates the worker, and one durable
  storage transaction leaves either the exact old or complete authenticated new vault after a crash.
- The exact bounded cohort set validates before decrypt, preventing an invalid/omitted decoy from acting as a
  selected-issuer oracle.
- Pre-allocation slot/epoch races discard the unsigned candidate and restart binding. Post-allocation reissuance is
  blocked pending a separately ratified supersession/nullifier-continuity transition.
- The presentation ABI remains V1/18 with exact root/time equality.

## Required runtime evidence

Implementation approval still requires randomized sparse-tree/path properties (including mixed directions),
replay/finality tests, multi-tab CAS and crash/restart drills, backup recovery, bounded non-sensitive observability,
mobile/load measurements and independent audits.

## Validation

- focused V2 vault/refresh contract test — PASS
- SDK TypeScript typecheck — PASS
- `git diff --check` — PASS
- dedicated CI workflow — correctly invokes the focused test and typecheck

**Reliability approval:** implement the parser, private refresh worker, resolver trust bundle and atomic storage
contract. Do not infer approval for live persistence, presentation, activation or allocated reissuance.
