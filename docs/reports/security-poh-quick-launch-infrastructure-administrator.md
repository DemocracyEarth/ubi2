# Security gate — Quick Launch infrastructure administrator boundary

- **Gate:** least authority, secret isolation, exact-resource mutation and compensating controls
- **Reviewer:** Codex security review
- **Date:** 2026-09-28
- **Verdict:** **PASS WITH EXPLICIT RESIDUAL — no AWS apply authorized**

## Controls verified

- The one-hour administrator cannot read secret values. It may only list metadata, inspect two exact
  references and apply exact release/purpose tags separately to each.
- VPC/subnet discovery is read-only. Only the two pre-approved subnet ARNs accept exact Base Sepolia,
  API-origin and release tags; tag deletion and all network creation/deletion are absent.
- ACM may request only `quick-launch-api.proofofhumanity.org` with DNS validation, RSA-2048 and exact
  release tags. Certificate inspection requires those resource tags. Route 53 can touch only the exact
  zone and only validation-shaped CNAME UPSERTs below that hostname.
- IAM can create/tag only `PoHQuickLaunchTaskExecutionRole`, inspect only that role and the exact
  `PoHQuickLaunchCloudFormationDeploymentRole`, and install an inline policy only while the task role has
  its exact resource tags. Managed-policy operations, `PassRole`, trust updates and deletion are absent.
- The task role's runtime authority is restricted to pulling one repository, writing one log-stream
  namespace, reading exactly two signer secrets and optionally decrypting their exact KMS keys through
  Secrets Manager. The application receives no task role.
- The policy contains no ECR API, CloudFormation, ECS, funding, blockchain, mainnet or Fobal
  authority. Fobal-named secret inputs and unrelated role names fail closed.

## Explicit residual authorization risk

IAM has no condition key for the trust bytes on `CreateRole` or inline policy name/document on
`PutRolePolicy`. Route 53 has no condition key for record value. The principal therefore has payload
discretion only on the exact task role and exact validation-shaped CNAME.

The required control is separate action-time confirmation against canonical hashes, immediate canonical
read-back, exact comparison to ACM's returned CNAME, CloudTrail evidence, zero attached managed policies
and prompt removal of the temporary assignment. A mismatch or unavailable read-back blocks the release;
it is not grounds to broaden the permission set.

**Security approval:** merge the transaction-free package; do not create, assign or use the permission
set without the protected live review and a fresh authorization.
