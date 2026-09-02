# Quick Launch dedicated API origin — Base Sepolia, transaction-free cutover

The public frontend remains the automatically deployed AWS Amplify application at
`https://proofofhumanity.org`. Amplify receives no signer, sponsor, secret-manager reference or
runtime environment dump. It receives one public build variable,
`POH_QUICK_LAUNCH_API_ORIGIN=https://<dedicated-host>`, which installs exact-path server rewrites for:

- `/api/self-verify`
- `/api/predicate`
- `/api/sponsored-mint`
- `/api/quick-launch-readiness`

The browser and Self callback continue to use the canonical `proofofhumanity.org` URLs. The rewrite
destination is one HTTPS ECS/Fargate task behind an Application Load Balancer. `/api/healthz` remains
direct-origin-only and exposes an allowlisted boot identifier for restart evidence.

This runbook is Base Sepolia only. The initial service must set
`POH_BLOCKCHAIN_TRANSACTIONS_ENABLED=false`; sponsored POST then returns HTTP 503 before parsing the
request, looking up a capability, reading a signer, calling RPC, consuming a quota or changing state.
Do not fund an account or submit a transaction during this slice.

## Why ECS/Fargate instead of Amplify or App Runner

The verification handoff is a bounded process-local store with a ten-minute TTL. Amplify does not
prove a sticky single Node process. App Runner temporarily adds capacity during deployments even when
steady-state min/max are one. The checked-in ECS service instead pins `DesiredCount: 1`,
`MaximumPercent: 100` and `MinimumHealthyPercent: 0`. ECS must stop the old task before starting the
new one, so deployment has downtime but never two workers. Horizontal or zero-downtime deployment is
blocked until a separately reviewed encrypted shared-store adapter exists.

## Required non-secret and metadata-only inputs

Do not retrieve either secret value. Obtain and independently verify:

1. Exact merged 40-hex source revision and an immutable ECR image URI using `@sha256:<64 hex>`.
2. Existing VPC and at least two public subnets in separate Availability Zones.
3. Dedicated hostname, public Route 53 zone ID and matching ACM certificate ARN.
4. Credential-free monitored Base Sepolia RPC URL. URLs containing userinfo, query credentials or
   fragments are rejected.
5. Immutable topology attestation and SHA-256 binding the account/region, cluster, service,
   `desiredCount=1`, deployment percentages, ALB/DNS path, image digest, revision and approver.
6. Approved issuer Secrets Manager reference metadata and immutable redacted attestation SHA-256.
   Its derived public address must equal `0x1D6cB99ff20223d730Ae5D4680EC5154B7FdAefe`.
7. A distinct approved sponsor Secrets Manager reference, its public address and immutable redacted
   attestation SHA-256. It must not equal the issuer, owner, deployer or a holder address.
8. Optional customer-managed KMS key ARNs for either secret. The task execution role is scoped to the
   two secret references and supplied KMS keys only.
9. A separately provisioned `PoHQuickLaunchTaskExecutionRole` ARN plus approved immutable hashes of
   its trust and permissions documents. It must pass the transaction-free account/region binding
   preflight and the exact [execution-role contract](QUICK_LAUNCH_TASK_EXECUTION_ROLE.md).
10. Deployment-owner approval for the billable Fargate, ALB, CloudWatch and Route 53 resources.

Secret references are deployment metadata and still must not be committed or copied into evidence.
Supply them through the protected deployment interface. Never run `get-secret-value`, print an
environment map, put a private key in a CloudFormation parameter, Docker build argument or Amplify
variable, or add one to an image layer.

## Build and infrastructure contract

The Docker build context is allowlisted by the repository `.dockerignore`. The image compiles the
canonical Self callback and public Base Sepolia defaults with `POH_BUILD_STANDALONE_API=true`, then
copies only the Next standalone server, static assets and public files into the runtime layer. The flag
is confined to the Docker build; the Amplify frontend keeps its existing Next output mode. Build from
the exact reviewed revision:

```sh
docker build --file apps/proofofhumanity/Dockerfile \
  --tag <private-ecr-repository>:<40-hex-revision> .
```

Scan the image, push it through the approved release workflow and resolve the registry-reported digest.
Tags do not satisfy the CloudFormation parameter pattern. Validate
[`aws/quick-launch-api-origin.yaml`](aws/quick-launch-api-origin.yaml), create a reviewed change set and
inspect it before execution. The template creates no secret and outputs no secret reference or value;
ECS injects only `ISSUER_PRIVATE_KEY` and `POH_SPONSOR_PRIVATE_KEY` from Secrets Manager at task start.

The template also creates no IAM resource and contains no secret-read policy. It requires a pre-created
`TaskExecutionRoleArn` that the stack can reference but cannot mutate. Before creating a change set,
run the redacting `quick-launch:execution-role-preflight` and verify the protected live role metadata
against the [exact least-privilege contract](QUICK_LAUNCH_TASK_EXECUTION_ROLE.md). An IAM role ARN is
regionless; the check binds it to the deployment account and binds every approved ECR, secret and KMS
resource to `us-east-1`.

The service has no task role and therefore no application-level AWS API authority. Its pre-created
execution role can pull the one digest-pinned image, write only the dedicated log streams and retrieve
exactly the two injected secrets. The task port accepts traffic only from the ALB security group. ALB
HTTP redirects to HTTPS and drops invalid headers. ECS Exec is disabled.

Do not execute the change set until the cost approval and every required input above exists. A local
template test is not deployed-infrastructure evidence.

## Transaction-free cutover order

1. Deploy the digest-pinned stack with `POH_BLOCKCHAIN_TRANSACTIONS_ENABLED=false` as fixed in the
   template. Confirm ECS reports desired/running/pending counts `1/1/0`; capture only redacted metadata.
2. Verify the direct origin before exposing canonical traffic:

   ```sh
   QUICK_LAUNCH_API_EVIDENCE_PHASE=before \
   QUICK_LAUNCH_API_ORIGIN=https://<dedicated-host> \
   QUICK_LAUNCH_EXPECTED_SOURCE_REVISION=<40 lowercase hex> \
     pnpm --filter @ubi2/proofofhumanity quick-launch:api-origin-preflight \
     > <approved-before-evidence-path>
   ```

   The checker performs two HTTPS GETs only. It never prints raw responses; it emits strict allowlists
   plus their SHA-256 digests and fails on extra fields, wrong runtime, enabled transactions, stale
   revision or non-ready signer/topology bindings.
3. In the Amplify main-branch configuration, add only
   `POH_QUICK_LAUNCH_API_ORIGIN=https://<dedicated-host>`. Ensure issuer/sponsor variables and secret
   references are absent from Amplify. Rebuild the same source revision and inspect build artifacts by
   metadata only; do not download or dump an environment file.
4. Confirm the automatic frontend revision, then run both existing transaction-free checks against the
   canonical domain:

   ```sh
   NEXT_PUBLIC_SELF_ENDPOINT=https://proofofhumanity.org/api/self-verify \
     pnpm --filter @ubi2/proofofhumanity quick-launch:preflight

   QUICK_LAUNCH_EXPECTED_SOURCE_REVISION=<40 lowercase hex> \
   QUICK_LAUNCH_EXPECTED_TOPOLOGY_ATTESTATION_SHA256=<64 lowercase hex> \
   QUICK_LAUNCH_EXPECTED_ISSUER_SECRET_ATTESTATION_SHA256=<64 lowercase hex> \
   QUICK_LAUNCH_EXPECTED_SPONSOR_SECRET_ATTESTATION_SHA256=<64 lowercase hex> \
     pnpm --filter @ubi2/proofofhumanity quick-launch:host-preflight
   ```

5. Verify canonical requests reach the same revision and readiness response as the direct origin.
   Redirects, a non-200 readiness record, a different response hash or any unknown field block cutover.

## Restart and redaction drill

Run this before any phone/Self session exists. Archive the successful `before` evidence, force one ECS
service deployment without changing image/config, and continuously record sanitized desired/running/pending
counts. With the checked-in deployment policy, the old task must stop before the replacement starts; a
brief 503 window is expected and overlap is a failure.

After the replacement is healthy, run:

```sh
QUICK_LAUNCH_API_EVIDENCE_PHASE=after \
QUICK_LAUNCH_API_ORIGIN=https://<dedicated-host> \
QUICK_LAUNCH_EXPECTED_SOURCE_REVISION=<40 lowercase hex> \
QUICK_LAUNCH_BEFORE_EVIDENCE_PATH=<approved-before-evidence-path> \
  pnpm --filter @ubi2/proofofhumanity quick-launch:api-origin-preflight \
  > <approved-after-evidence-path>
```

The after record passes only when the source revision is unchanged, the boot ID changes, the start time
advances, both public records remain strict allowlists and transactions remain disabled. Hash and publish
both records and the redacted ECS deployment-event metadata immutably. Never include task environment,
request bodies, verification sessions, credential contents, RPC URLs, secret references or log lines.

For later maintenance after users exist, first remove the Amplify proxy variable, deploy the fail-closed
frontend, wait longer than the ten-minute handoff TTL, and only then restart the single task. Re-enable the
proxy only after direct and canonical checks pass. Do not attempt zero-downtime overlap.

## Rollback and exact blockers

Rollback is fail-closed: remove `POH_QUICK_LAUNCH_API_ORIGIN` from Amplify and rebuild. The compiled API
routes on Amplify return `dedicated-api-origin-required`; they cannot read a signer. Do not point the
variable at `proofofhumanity.org`, HTTP, localhost, a credential-bearing URL or a URL with a path/query.

Live completion is blocked until all items below are observed:

- [ ] Billing-impact approval to create/use Fargate, ALB, CloudWatch and Route 53 resources.
- [ ] VPC, two-AZ subnet, hosted-zone, hostname and ACM certificate inputs.
- [ ] Digest-pinned ECR image built from the exact merged revision and approved image-scan result.
- [ ] Credential-free monitored Base Sepolia RPC selection and provider/outage owner.
- [ ] Metadata-only approved issuer and sponsor secret references, KMS metadata where applicable, and
      distinct derived public addresses.
- [ ] Pre-created same-account `PoHQuickLaunchTaskExecutionRole`; protected live trust/inline-policy
      review matches the exact contract, and redacted account/region preflight reports `ready: true`.
- [ ] Three immutable redacted attestation URLs/paths and exact SHA-256 values.
- [ ] Direct-origin before/restart/after evidence proving one task, a boot transition and no overlap.
- [ ] Amplify artifact/config metadata proving the only API-origin variable is public and no signer or
      secret reference entered the frontend build/runtime.
- [ ] Canonical public and host preflights match the direct origin and report `ready: true` while
      `transactionFree: true`.
- [ ] External immutable anchor for the evidence bundle and deployment-owner approval.

Until every item passes, do not claim live readiness, scan a passport, fund the sponsor, enable the
transaction flag, submit any transaction, deploy mainnet or resume custom-circuit Phase 2 work.
