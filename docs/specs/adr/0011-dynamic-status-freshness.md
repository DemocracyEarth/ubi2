# ADR-0011 — Bind dynamic status to an exact governed snapshot timestamp

- **Status:** proposed
- **Date:** 2026-08-14
- **Deciders:** product owner, architect, cryptography engineer and security auditor
- **Related:** [ADR-0010](0010-direct-v2-portable-zk-credential.md),
  [EVM ZK Identity v2](../10-evm-zk-identity-v2.md)

## Context

Sanctions and similar mutable checks cannot inherit the lifetime of the long-lived passport credential. The v2
public-signal layout reserved signal 17 as a `uint32` dynamic-status epoch, and the canonical SDK policy already
commits to a provider, list version, status root and maximum age. Until now the EVM adapter rejected every non-zero
value because three security properties were unspecified:

1. the time unit and authority behind signal 17;
2. how the signal is tied to the exact status root committed by the policy;
3. whether freshness is global, provider-selected or consumer-selected.

Accepting a holder- or issuer-chosen timestamp would let an old root be relabeled as fresh. Using block numbers
would create different semantics across Ethereum, Base, Celo, World Chain and Robinhood Chain. A global adapter
window would also let one consumer silently weaken another consumer's policy.

## Decision

1. **Signal 17 is a Unix timestamp in seconds.** It is the publication time of the exact dynamic-status snapshot,
   not the time a holder generated a proof or received a short-lived credential. The field name `statusEpoch`
   remains for ABI compatibility; its unit is now pinned.
2. **The canonical policy hash commits to the complete public rule:** fixed status kind `sanctions-clear`, hashed
   provider identifier, hashed list-version identifier, status root and `maximumAgeSeconds`.
3. **Governance registers the exact policy hash.** The registry recomputes it from those canonical inputs and stores
   the snapshot publication timestamp. A zero or future publication time is rejected. Maximum age is bounded to
   60 seconds through 365 days, matching the SDK schema.
4. **The proof must reproduce that timestamp exactly.** For a registered dynamic policy, signal 17 must be non-zero
   and equal the registry's `publishedAt`. This prevents a valid old root from being presented with a newer clock.
5. **Freshness is inclusive at the boundary.** The adapter accepts when
   `block.timestamp - publishedAt <= maximumAgeSeconds`; it rejects future timestamps and becomes stale one second
   after the configured maximum age.
6. **Non-dynamic policies use zero.** The circuit must constrain signal 17 to zero for a non-dynamic policy. A
   non-zero signal for an unregistered policy fails closed. A sound production circuit remains responsible for
   proving that a dynamic policy cannot be encoded with zero.
7. **Retirement is exact and irreversible.** Governance may retire a policy hash immediately. Old and new snapshots
   may overlap while active so consumers can migrate without an implicit `latest` race; consumers always request
   an exact policy hash.
8. **No production activation follows from this ADR.** The current adapter and registry remain pre-deployment. A
   production circuit must prove the canonical policy relation and status-root membership, and its artifacts,
   ceremony, Solidity integration and operational source of sanctions snapshots require independent review.

## Security properties

- A holder cannot refresh a stale snapshot by changing the public timestamp.
- Provider, list version, root or maximum age substitution changes the policy hash and invalidates the requested
  policy binding.
- A consumer that requests a 24-hour policy cannot silently receive a one-year policy; they are different hashes.
- Governance retirement invalidates the exact snapshot even if its wall-clock age remains inside the window.
- Chain timestamp manipulation is limited to the destination chain's consensus assumptions. Consumers needing a
  tighter guarantee must choose a shorter maximum age and should not use a value near normal sequencer skew.

## Operational consequences

The status publisher must make a new root, list version and publication timestamp available before the previous
policy expires. Applications should fetch an authenticated policy manifest and display its provider, list version,
publication time and expiry before requesting a proof. They must not ask for an ambiguous `latest` status.

The registry owner is a trust root for which public snapshots are accepted. Production ownership therefore remains
a timelocked multisig, and publication tooling must verify the canonical SDK hash before proposing a transaction.
An authorized but incorrect sanctions root remains an operational/provider failure; this mechanism makes the root
and timing auditable but does not judge the source list's correctness.

## Rejected alternatives

- **Proof-generation or credential-issuance time:** the holder or issuer could issue a fresh timestamp against an
  old list, breaking root freshness.
- **Destination-chain block number:** block cadence and finality differ across target EVM chains.
- **One global maximum age in the adapter:** consumers have different risk tolerances and the policy already commits
  to the requested window.
- **Implicit latest-root lookup:** in-flight proofs race governance updates and cannot state which public list was
  actually proven.
- **Store sanctions-clear in the passport credential or NFT:** mutable status would outlive the source list and
  create a false durable assurance.

## Ratification gate

Accept this ADR only after security review confirms the circuit will enforce the zero/non-zero policy-kind rule and
bind the exact canonical dynamic-status policy hash. Mainnet still requires the full Stage 5 audit and release gate.
