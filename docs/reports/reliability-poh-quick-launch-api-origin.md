# Reliability gate — PoH Quick Launch dedicated API origin

- **Gate:** one-process state continuity, restart observability and reproducible routing
- **Reviewer:** Codex reliability review
- **Date:** 2026-08-30
- **Verdict:** **PASS — implementation only; live infrastructure remains blocked**

## Properties verified

- The public hostname stays stable while exact-path Amplify rewrites isolate the stateful APIs behind one origin.
- ECS pins `DesiredCount: 1`, `MaximumPercent: 100` and `MinimumHealthyPercent: 0`. For a one-task rolling service,
  the capacity ceiling forces stop-before-start replacement; documented downtime is accepted to avoid two
  independent ten-minute handoff stores.
- The ALB health path becomes healthy only for the dedicated role with transactions disabled. A boot UUID,
  process-start timestamp and exact source revision support before/after restart evidence without request data.
- The external checker performs GETs only, binds source revision and strict response fields, hashes the raw bytes
  without emitting them and proves the replacement boot differs while the revision remains constant.
- The runbook requires direct-origin checks before canonical cutover, a no-overlap restart drill, canonical/direct
  response comparison and a fail-closed rollback. Future maintenance drains the ten-minute store before restart.

## Residual gates

- Fargate/ALB/DNS/ACM inputs and billing approval were not supplied, so no service exists from this slice.
- The digest-pinned image, provider metadata, one-task event sequence and before/after records must be observed.
- Process-local state still mandates downtime. Zero-downtime or horizontal scaling requires a separately reviewed
  encrypted shared-store design.
- The public transaction kill switch intentionally prevents the complete sponsored mint journey.

**Reliability approval:** merge the reproducible one-task contract; keep live readiness false until external
topology, restart and routing evidence passes.
