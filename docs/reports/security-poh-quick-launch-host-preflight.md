# Security gate — PoH Quick Launch host preflight

- **Gate:** secret hygiene and transaction-free operational evidence
- **Reviewer:** Codex security review
- **Date:** 2026-08-30
- **Verdict:** **PASS — no Critical/High in tooling; live host remains blocked**

## Controls verified

- No private key, password, secret value, seed phrase, environment map or raw secret-manager reference enters the
  response or captured evidence. Attestation digests bind separate immutable redacted artifacts.
- Private keys are used only to derive public addresses for comparison; the route has no wallet client, RPC URL,
  signing call or transaction path.
- Unknown response strings are discarded by the external verifier. Schemas, release IDs, origin, callback,
  environment and blocker names are exact allowlists; revisions, digests and addresses receive strict validation.
- The sponsor must be non-zero and distinct from the owner and approved issuer. Invalid caps, allowlists or key
  material fail closed without returning parser errors that could contain configuration.
- Readiness responses are dynamic, non-cacheable and `nosniff`; the external verifier rejects redirects and any
  non-canonical origin.
- Operational instructions permit only secret metadata/attachment checks and explicitly prohibit value retrieval,
  environment dumps, funding, public transactions, mainnet deployment and custom-circuit Phase 2 work.

## Findings

- **Critical/High:** none in this slice.
- **Blocking operational gap:** provider access and immutable redacted attestations were not supplied. This is not
  waived; the live record remains non-ready.
- **Residual trust:** a self-declared runtime topology string is not proof. Readiness also requires the expected
  external topology digest and human verification of its immutable public artifact.

**Security approval:** merge the fail-closed public boundary. Do not expose provider paths, inspect secret values or
authorize sponsored use until the external evidence chain passes.
