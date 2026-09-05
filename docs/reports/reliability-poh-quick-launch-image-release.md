# Reliability gate — PoH Quick Launch image provenance

- **Gate:** deterministic source-to-image binding and reproducible handoff
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-04
- **Verdict:** **PASS — local candidate only; deployment remains blocked**

## Properties verified

- The build recipe freezes the source commit, Git-archive boundary, dependency lock, platform, base-image
  digests, commit-derived build identifiers and generated-file timestamps.
- Next build randomness and JSON ordering are normalized only during the build. Runtime randomness is not
  modified. Preview/draft mode and non-empty Server Actions manifests are rejected before packaging.
- Independent no-cache builds must converge on one image digest. The evidence record retains both digests
  and refuses publication review if they differ.
- SBOM, vulnerability reports, scan summary and source-to-image binding are independently hash-addressed.
  Evidence directories cannot be overwritten by reruns.
- The final runtime contains the standalone server rather than a development server or builder toolchain,
  and its environment-key set is compared exactly rather than checked as a permissive subset.

## Residual gates

- No ECR bytes or remote registry scan were observed. A later approved publication must compare the
  registry-reported digest with the local digest and retain repository scan evidence.
- No IAM role, ECS task or canonical path was created or changed. Live service start, restart, redaction,
  routing and transaction-disabled preflights remain external gates.

**Reliability approval:** merge the deterministic build and evidence contract; keep deployment/readiness
blocked until the separately approved publication and service evidence pass.
