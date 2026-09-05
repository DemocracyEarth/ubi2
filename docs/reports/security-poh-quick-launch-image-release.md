# Security gate — PoH Quick Launch API image and publisher boundary

- **Gate:** local supply-chain scanning, secret exclusion and least-authority publication contract
- **Reviewer:** Codex security review
- **Date:** 2026-09-04
- **Verdict:** **PASS — zero open Critical/High locally; no live IAM/publication approval**

## Controls verified

- The Docker build accepts no signer secret, secret reference, AWS credential or registry credential. Image
  history is scanned for forbidden credential/reference names and runtime environment values are never
  emitted into provenance.
- The runtime is a digest-pinned distroless non-root image. The locked application dependency set and OS
  packages pass the zero-Critical/High local Docker Scout policy.
- Next's patched PostCSS dependency is enforced by an exact-version pnpm read hook whose bytes and lockfile
  checksum are provenance-bound; the V2-frozen root package manifest remains byte-identical.
- Provenance declares `imagePublished: false`; missing or true publication state fails closed. Neither the
  build nor the policy renderer makes an AWS call.
- `PoHQuickLaunchImagePublisherRole` is assumable only through the account's
  `AWSReservedSSO_PoHQuickLaunchDeployer_*` role, has a 3,600-second maximum session and can obtain an ECR
  token only in `us-east-1`.
- Repository permissions are limited to layer upload/manifest publication and read/scan verification on
  the exact `proof-of-humanity` repository ARN. The matching deployer grant permits only
  `sts:AssumeRole` on this one publisher role.
- The role cannot create, delete, tag or administer repositories; delete images; mutate IAM; read secrets
  or KMS keys; deploy ECS/CloudFormation; or access another repository.

## Findings and external blockers

- **Critical/High:** none in the locally scanned committed candidate.
- ECR does not provide an IAM image-tag condition for `PutImage`; therefore the repository's immutable-tag
  setting and the later one-time exact revision/digest publication procedure are mandatory controls.
- Live repository metadata, policy equality, principal identity, registry digest/scan and immutable evidence
  were not inspected by this slice and must not be inferred from the generated documents.

**Security approval:** merge the code-only build and least-authority contract. Pause before IAM mutation or
image publication, and do not retrieve secrets, fund accounts, transact, deploy application resources or use
mainnet.
