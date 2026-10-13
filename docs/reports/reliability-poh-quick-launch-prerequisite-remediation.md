# Reliability gate — Quick Launch prerequisite remediation

- **Date:** 2026-10-13
- **Verdict:** **PASS for the local package; live prerequisites remain blocked**

The package makes partial state visible and recoverable without pretending it is complete. Issuer and
sponsor containers are created separately and each must read back with zero versions. The subnet approval
binds both routing paths and AZs in one canonical record. Role creation and policy installation are separate
calls with trust, tags, policy, attached-policy count and session duration read back after each step.

All eight mutations—three permission-set bootstrap calls and five remediation calls—require a fresh pause.
No retry is implicit. An already-created exact resource is inspected and compared; any mismatch stops the
lane instead of overwriting it. Service-linked ECS/ELB roles are not auto-created and must pass preflight.

The CloudFormation service role includes rollback/delete operations only for the named/tagged resources in
the one future stack. It has no CloudFormation control-plane authority, so this package cannot create or
execute a stack or change set. Generated-resource wildcards and payload fields that IAM cannot constrain are
recorded as residual limitations and must be controlled by a later hash-bound change-set review.

No restart, failover, external HTTPS, transaction or live AWS evidence was exercised. Those remain release
gates after the prerequisites exist.

The 2026-10-13 corrective re-gate adds the AWS 32-character permission-set-name invariant directly to the
renderer. The rejected 39-character name now fails locally, before any request plan is emitted; the replacement
`PoHQuickLaunchPrereqAdmin` is 25 characters. The rejected live package binding is revoked, and a future live
attempt must use a freshly rendered and separately approved package. No automatic retry exists.
