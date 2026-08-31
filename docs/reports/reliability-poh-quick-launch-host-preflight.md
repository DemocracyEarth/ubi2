# Reliability gate — PoH Quick Launch host preflight

- **Gate:** release-candidate identity, topology and configuration reproducibility
- **Reviewer:** Codex reliability review
- **Date:** 2026-08-30
- **Verdict:** **PASS — tooling only; live host remains blocked**

## Properties verified

- A 40-hex source revision and three exact 64-hex public attestation digests bind the deployed bytes, sticky-node
  topology and two secret-injection events without publishing provider paths or secret material.
- The host record derives only public signer addresses in memory and performs no RPC call, signing operation or
  transaction submission.
- The checker accepts only `https://proofofhumanity.org`, disables redirects and records response hashes and HTTP
  status alongside a timestamp. A missing endpoint, stale deployment, cache mismatch or absent expected digest
  makes the evidence non-ready.
- The sponsor policy is constrained to chain ID 84532 and a distinct address. Missing or invalid budget/rate-limit
  configuration prevents the policy-valid bit from becoming true.
- CloudFront delivery is recorded only as an observation. It is never treated as evidence of a single sticky Node
  origin or durable voucher state.

## Observed release candidate

- The live HTTPS homepage returned 200 and contained the Quick Launch/Base Sepolia markers.
- The removed demo-credential endpoint returned 404.
- The public Base Sepolia contract/callback preflight passed read-only checks.
- The readiness endpoint was not yet present on the merged base, and deployment-provider metadata plus immutable
  topology/secret-injection attestations were unavailable. The captured evidence therefore correctly says
  `ready: false`.

## Residual gates

- A deployment owner must prove one sticky Node origin and publish the immutable topology attestation.
- The deployment owner must verify the approved issuer and sponsor secret-manager references by metadata only and
  publish redacted injection attestations. The sponsor public address must be distinct from owner/issuer.
- After merge and automatic deployment, the external verifier must observe this exact revision and all three
  expected digests before any phone/Self journey or sponsored transaction is attempted.

**Reliability approval:** merge the checker and readiness record; do not call the host ready from the present
blocked evidence.
