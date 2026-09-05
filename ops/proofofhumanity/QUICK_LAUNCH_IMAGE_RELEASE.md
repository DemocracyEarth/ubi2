# Quick Launch image build, provenance and publisher-role contract

This runbook prepares the transaction-disabled Base Sepolia API image for a later, separately
approved ECR publication. It performs no AWS call, obtains no registry credential, reads no secret,
funds no account and sends no blockchain transaction. A successful local record is evidence that one
exact source revision is reproducible and eligible for publication review; it is not permission to
create IAM resources, push an image or deploy the API service.

## Frozen build boundary

The release image is built only for `linux/amd64`, matching the ECS task definition. The builder uses
an immutable official Node base:

```text
docker.io/library/node:22-bookworm-slim@sha256:4d676821dff059fd00d277ee4261ef34ea712317fed0737c03941481b5760c96
```

The final runtime uses the non-root, shell-free distroless Node 22 Debian 13 image and excludes the
builder's package manager and toolchain:

```text
gcr.io/distroless/nodejs22-debian13:nonroot@sha256:9a052c12c6501f1248b682bf6d022276220cb2a65416d215e0973527394d1552
```

Its runtime image environment is restricted to `HOSTNAME`, `NEXT_TELEMETRY_DISABLED`, `NODE_ENV`,
`PATH`, `PORT` and the distroless certificate path `SSL_CERT_FILE`; any additional key fails closed.

The build requires an exact 40-character commit and embeds it as the OCI
`org.opencontainers.image.revision` label. The builder never consumes the ambient worktree. It creates
a Docker context from `git archive <revision>` containing only `.dockerignore`, `.pnpmfile.cjs`, the
workspace lock and manifest files, `apps/proofofhumanity`, and `packages/sdk`. Untracked files, dotenv
files, private keys, operator evidence and other monorepo projects cannot enter that context. The
pnpm read hook is narrowly version-gated and replaces only Next 15.5.25's PostCSS dependency with
8.5.28; its own SHA-256 is part of the provenance recipe. This keeps the security patch reproducible
without changing the V2-frozen root package manifest.

The standalone build uses `tsconfig.standalone.json`, which typechecks only application code and
generated Next route types. Test programs, release scripts and their redacted operational fixtures are
validated before the image build but are not dependencies of the runtime image or Docker context.

[`build-quick-launch-image.sh`](build-quick-launch-image.sh) performs two independent no-cache builds
with the exact commit as the Next build ID and the commit timestamp as `SOURCE_DATE_EPOCH`. Before the
runtime copy, Next's build-only preview/request identifiers and generated JSON ordering are made
commit-deterministic, and generated-file timestamps are normalized to that epoch. The normalizer
fails if application source enables preview/draft mode or if the server-action manifest contains any
action: the revision-derived build bytes are never permitted to become runtime authentication
secrets. The standalone server, static assets and public assets are assembled into one normalized
release tree and copied into the runtime as one layer so destination-directory timestamps cannot
affect the digest. Different image digests fail closed. The script then:

1. verifies that the runtime environment-key names are exactly the public base/runtime allowlist;
2. rejects credential or secret-reference names in Docker history;
3. produces an SPDX JSON SBOM with Docker Scout;
4. produces separate Critical and High SARIF reports and requires both counts to be zero;
5. hashes the Git archive, Dockerfile, `.dockerignore`, `.pnpmfile.cjs`, lockfile, SBOM and scan summary;
6. emits a redacted source-to-image provenance record and its canonical SHA-256.

Docker and Docker Scout must already be installed. Advisory-database retrieval may require network
access, but scanning targets the local image (`local://...`). Do not authenticate Docker to ECR for this
step. Run only after the candidate source has been committed:

```sh
revision="$(git rev-parse HEAD)"
ops/proofofhumanity/build-quick-launch-image.sh "$revision"
```

The default non-overwriting output is ignored by Git at:

```text
apps/proofofhumanity/quick-launch-image-evidence/<revision>/
```

This directory is separate from Playwright's disposable `test-results/` tree, which the browser gate
cleans before each run.

Archive these files only in the approved immutable evidence store. Do not add local Docker metadata or
scanner output to Git without a separate privacy review. The public allowlisted record is
`provenance.json`; hash comparison must use the adjacent `provenance.sha256`.

## Exact image-publisher role

Image publication uses a separate role named `PoHQuickLaunchImagePublisherRole`. It is not the ECR
bootstrap role, CloudFormation role, ECS task execution role or application task role. Its maximum
session duration is 3,600 seconds. It may be assumed only by the account's IAM Identity Center role
whose IAM principal ARN matches:

```text
arn:aws:iam::<ACCOUNT_ID>:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PoHQuickLaunchDeployer_*
```

Generate the exact account-bound trust and inline-permissions documents locally:

```sh
QUICK_LAUNCH_AWS_ACCOUNT_ID=<12-digit-staging-account> \
  pnpm --silent --filter @ubi2/proofofhumanity quick-launch:image-publisher-role \
  > <protected-new-output-path>
```

The command makes no AWS call. The output contains only the non-secret account/repository identifiers,
exact documents and canonical hashes. It defines one inline policy named
`PoHQuickLaunchImagePublisher`, no attached managed policy, and the exact one-statement
`sts:AssumeRole` grant that must be merged into the existing `PoHQuickLaunchDeployer` permission-set
policy. That grant targets only `arn:aws:iam::<ACCOUNT_ID>:role/PoHQuickLaunchImagePublisherRole`;
never replace the permission set's other reviewed statements with this fragment.

| Purpose | Allowed actions | Resource |
|---|---|---|
| Obtain a short-lived ECR login token | `ecr:GetAuthorizationToken` | `*`, conditioned to `us-east-1` |
| Upload one image | `ecr:BatchCheckLayerAvailability`, `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload`, `ecr:PutImage` | `arn:aws:ecr:us-east-1:<ACCOUNT_ID>:repository/proof-of-humanity` |
| Verify digest, empty state and registry scan | `ecr:BatchGetImage`, `ecr:DescribeImageScanFindings`, `ecr:DescribeImages`, `ecr:DescribeRepositories`, `ecr:ListImages`, `ecr:ListTagsForResource` | the same exact repository |

Every repository action is conditioned to `aws:RequestedRegion=us-east-1`. The role has no repository
creation/deletion/tagging/policy authority, no IAM mutation, no secret/KMS/log/ECS/CloudFormation
access, no image deletion and no permission for another repository. Repository tag immutability is a
separate live prerequisite and prevents replacement of an existing revision tag.

## Failure paths

Publication review is blocked when any of these conditions holds:

- source revision is abbreviated, missing or not an available commit;
- output evidence path already exists;
- base image is not the pinned linux/amd64 digest;
- either no-cache build produces a different digest;
- Docker image configuration contains an environment key outside the fixed allowlist;
- Docker history contains a credential or secret-reference name;
- SBOM or either SARIF report cannot be produced;
- Critical or High findings are nonzero;
- provenance input contains malformed hashes, a non-amd64 platform or an image-publication claim;
- publisher trust differs from the exact SSO role pattern;
- the deployer permission-set addition differs from the exact role-specific `sts:AssumeRole` grant;
- publisher permissions contain an extra action/resource, another region/repository or an attached
  managed policy.

Run the source failure-path gate with:

```sh
pnpm --filter @ubi2/proofofhumanity test:quick-launch-image
```

## Publication remains paused

Before any IAM mutation or `docker push`, obtain a new action-time approval covering the exact role
documents and hashes. Then verify the live repository is `proof-of-humanity` in account/region, AES-256
encrypted, immutable, scan-on-push, correctly tagged and still empty. Publication must use the reviewed
commit tag once, resolve the registry-reported `sha256:` digest, wait for the ECR scan, and compare the
published digest to the locally reproduced digest. Stop before ECS/CloudFormation deployment.

No local artifact, policy hash or successful scan authorizes mainnet, application-resource creation,
secret retrieval, account funding, blockchain transactions or custom-circuit Phase 2 work.
