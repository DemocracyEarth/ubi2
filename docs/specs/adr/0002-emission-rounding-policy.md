# ADR-0002 — Emission rounding: bounded truncation for M1, revisit before M2

- **Status:** accepted (for M1) — revisit before M2/M5
- **Date:** 2026-06-21
- **Deciders:** architect + reliability-engineer + qa-engineer (cycle 1 gates)

## Context
Emission is `pending = UBI * elapsed_secs / EMISSION_PERIOD_SECS` with `UBI = 10^18` and
`EMISSION_PERIOD_SECS = 3600`. Because `10^18 % 3600 = 2800`, integer (truncating) division drops a
sub-unit remainder. The cycle-1 reliability and QA gates found that settling at non-hour-aligned
timestamps therefore loses **≤1 attowei (1e-18 UBI) per settlement boundary**, always a *loss*, never
a gain. (The original `settle_is_idempotent_in_total` test missed this by only using hour-aligned points.)

This matters because settlement frequency rises in later milestones (M2 streams, M5 demurrage), which
would accumulate many tiny truncations.

## Decision
**Accept the bounded truncation for M1.** It does not violate invariant I2: the computation is a pure,
deterministic integer function of `(state, timestamp)`, so two nodes on the same operation sequence
reach byte-identical state, and UBI is never created (the error is strictly conservative). The loss is
~1e-18 UBI per settle — far below the wallet's 4-decimal display and economically meaningless at M1.

**Revisit before M2** with a canonical rounding policy, options being: (a) carry the division remainder
in `Account` so emission is exact across settlements, or (b) formally document the bounded one-directional
loss as intended protocol behavior. The choice will be its own ADR once M2's higher settlement frequency
makes the trade-off concrete.

## Consequences
- M1 ships with simple, fast, deterministic emission math; no consensus risk.
- A tracked follow-up exists (board backlog) to pick a rounding policy before settlement frequency grows.
- Tests now include non-hour-aligned timelines (`crates/runtime/tests/i2_determinism.rs`) so any change
  to this behavior is caught.
