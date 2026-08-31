# Security gate — PoH Quick Launch dedicated API origin

- **Gate:** signer isolation, runtime secret injection, transaction kill switch and evidence redaction
- **Reviewer:** Codex security review
- **Date:** 2026-08-30
- **Verdict:** **PASS — no open Critical/High in code; no live-readiness claim**

## Controls verified

- The Docker context is an allowlist and excludes environment files, keys, secrets, local agent state, build output
  and unrelated monorepo contents. The runtime image receives no secret build argument or layer.
- CloudFormation accepts two Secrets Manager ARNs as `NoEcho` metadata, injects them through ECS `Secrets`, scopes
  the execution role to those references and optional KMS keys, and never creates or outputs a secret value.
- The application task has no AWS task role, ECS Exec is disabled, the task port accepts only ALB traffic, HTTPS is
  mandatory, invalid headers are dropped and only a credential-free public Base Sepolia RPC URL is accepted.
- Amplify receives one public origin URL only. Every compiled signing route independently requires the dedicated
  role, closing accidental local fallthrough if a rewrite is absent or malformed.
- The transaction flag defaults fail-closed and the checked-in deployment fixes it false. Unit/integration failure
  tests prove a malformed RPC and request body cannot move execution past the guard.
- Health/readiness/evidence outputs use exact public allowlists. Unknown fields fail without being echoed; keys,
  secret references, environment maps, request bodies, sessions and log lines are excluded from evidence.

## Findings

- **Critical/High:** none in this implementation slice.
- **Blocking external inputs:** no approved secret-reference metadata, KMS metadata, image scan/digest, certificate,
  topology attestation, restart event chain, Amplify artifact attestation or external anchor was supplied.
- **Availability tradeoff:** stop-before-start causes a 503 window. This is deliberate and safer than state split;
  the maintenance/drain procedure is mandatory once users exist.
- **Transaction path:** remains disabled and was not exercised. Enabling it requires a separate reviewed slice and
  observed sponsor funding/budget/outage evidence.

**Security approval:** merge the transaction-free origin boundary. Do not provision without cost approval, inspect
secret values, place any signer/reference in Amplify, enable transactions, deploy mainnet or begin Phase 2.
