# QA gate — PoH Quick Launch reproducible API image

- **Gate:** reproducible build, SBOM, zero-Critical/High scan and publication failure paths
- **Reviewer:** Codex QA review
- **Date:** 2026-09-04
- **Scope:** transaction-disabled Base Sepolia API image candidate only
- **Verdict:** **PASS — local build evidence only; no registry/publication claim**

## Acceptance evidence

- The builder accepts only an exact 40-character commit and constructs its context from a Git archive
  allowlist. Untracked files, dotenv files, operator evidence and unrelated workspaces cannot enter it.
- Builder and runtime images are digest-pinned. The final image is non-root and shell-free, contains one
  normalized standalone release tree and exposes only the fixed public runtime environment-key allowlist.
- Two independent no-cache `linux/amd64` builds of the committed candidate produce the same OCI digest.
- Docker Scout emits an SPDX JSON SBOM plus separate Critical and High SARIF reports. Both severity counts
  are required to be zero before the provenance checker can pass.
- The canonical provenance binds source revision/archive, Dockerfile, `.dockerignore`, the version-gated
  pnpm dependency hook, lockfile, both base images, platform, image digest, SBOM and scan-summary hashes.
  The local output path is non-overwriting.

## Failure coverage

- Invalid/abbreviated revisions, an existing evidence directory, an unpinned base, wrong platform,
  mismatched build digests, Critical/High findings, an added runtime environment key and any publication
  claim all fail closed.
- Publisher-document tests require the exact one-hour role, SSO trust condition, ECR action/resource
  allowlist and role-specific deployer assume-role grant. Repository administration, deletion, tagging,
  IAM, Secrets Manager and KMS actions remain absent.

**QA approval:** merge the reproducible local supply-chain gate. Image publication and AWS IAM mutation
remain separate action-time approvals.
