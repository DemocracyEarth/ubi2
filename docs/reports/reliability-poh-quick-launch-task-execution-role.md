# Reliability gate — PoH Quick Launch pre-created task execution role

- **Gate:** deterministic deployment input and fail-closed operational handoff
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-02
- **Verdict:** **PASS — implementation only; deployment remains blocked**

## Properties verified

- The application stack has one immutable IAM dependency instead of owning a mutable role lifecycle. Stack
  replacement or rollback cannot silently recreate or broaden execution authority.
- Account/region checks are deterministic, offline and strict. IAM's empty region field is checked separately
  from the `us-east-1` resource bindings, avoiding a false claim that IAM roles themselves are regional.
- Checker output is a fixed public schema of booleans/blocker codes; it omits all role, image, secret and KMS
  references. Invalid input exits non-zero without echoing the rejected value.
- The runbook makes policy changes an independently reviewed maintenance event and requires proxy removal or
  zero desired tasks, immutable policy hashes, a rerun of the binding preflight, change-set inspection and the
  existing no-overlap restart drill.

## Residual gates

- No live role or protected IAM document was inspected. Existence, trust bytes, permissions bytes and immutable
  approvals remain external blockers.
- No stack/service exists, so one-task continuity, task start, secret injection, log delivery, restart and
  canonical routing are unobserved.
- The transaction kill switch remains fixed false; this slice cannot establish sponsored-mint readiness.

**Reliability approval:** merge the deterministic handoff contract; retain `ready: false` until protected live
metadata and all direct/restart/canonical evidence pass.
