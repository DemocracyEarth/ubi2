# Security gate — PoH Quick Launch pre-created task execution role

- **Gate:** IAM ownership separation, least privilege and redaction
- **Reviewer:** Codex security review
- **Date:** 2026-09-02
- **Verdict:** **PASS — no open Critical/High in code; no live-role approval**

## Controls verified

- CloudFormation has no IAM resource, policy attachment or secret/KMS read statement. The deployment service role
  therefore does not need IAM create/update/attach/delete authority for the API-origin stack.
- The role name and ARN shape are constrained; the checker rejects wrong accounts, non-empty IAM region fields,
  cross-region or cross-account ECR/Secrets Manager/KMS references, tag-based images and a shared signer secret.
- The exact external contract allows only ECR authorization, pull from one repository, writes to one log group's
  streams, reads of two exact secrets and optional decrypt on exact keys through regional Secrets Manager.
- Attached managed policies, broad service actions, wildcard repository/secret/key access, alternate principals,
  missing source conditions, task-role access and ECS Exec are explicitly forbidden.
- The preflight never calls AWS and its output never includes input ARNs or environment values. The runbook forbids
  shell tracing, environment dumps, dotenv commits, secret-value retrieval and public policy documents containing
  raw secret references.

## Findings and external blockers

- **Critical/High:** none in the implementation.
- The preflight proves syntax/binding, not live role existence or policy equality. A protected decoded-policy
  comparison plus immutable canonical document hashes is mandatory before a change set.
- Role creation, policy approval, certificate/image/signer attestations, runtime injection and restart evidence
  were not performed and must not be inferred from this review.

**Security approval:** merge the least-authority boundary. Do not deploy from root, grant the deployment principal
secret-value access, place the role/signer references in Amplify, enable transactions or deploy mainnet.
