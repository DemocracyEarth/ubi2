# Quick Launch host preflight — automatic main deployment

`main` is automatically published as the public frontend at `https://proofofhumanity.org`. A successful
merge or a `200` home page is not API host-readiness evidence: the CloudFront front door does not prove
which origin handled two requests, how many Node processes exist, or where a signing variable was
injected. The signing/state APIs belong on the dedicated origin described in
[`QUICK_LAUNCH_API_ORIGIN.md`](QUICK_LAUNCH_API_ORIGIN.md), never in Amplify.

This runbook is transaction-free. It must never call a wallet, submit a chain transaction, retrieve a
secret value, print an environment, or copy a raw secret-manager path into public evidence.

## Required immutable inputs

Obtain three redacted, immutable artifacts from the deployment owner:

1. **Topology attestation.** Bind the canonical origin and branch to one sticky Node process, the
   provider/application identifier, min/max replica count of one, ingress-to-origin routing, restart
   behavior, trusted-proxy handling, log redaction, timestamp and approver. CloudFront headers alone
   are insufficient.
2. **Issuer injection attestation.** Bind `ISSUER_PRIVATE_KEY` to the approved secret-manager reference
   commitment and public address `0x1D6cB99ff20223d730Ae5D4680EC5154B7FdAefe`. Include provider,
   application/branch, metadata timestamp and approver. Exclude the secret value and raw reference.
3. **Sponsor injection attestation.** Bind `POH_SPONSOR_PRIVATE_KEY` to a different approved reference
   commitment and its public Base Sepolia address. Prove it is not the issuer, contract owner, deployer
   or holder, and bind `POH_SPONSOR_TESTNET_CHAIN_IDS=84532`. Exclude the secret and raw reference.

Publish each artifact immutably or place it in an approved evidence store, then calculate its SHA-256.
The three digests are public and are the only secret-provenance inputs accepted by the host preflight.

Provider metadata inspection must use description/list operations only. For AWS Secrets Manager that
means `describe-secret`; never call `get-secret-value`. Query only the metadata fields needed to build
the redacted attestation. Do not capture an Amplify environment-variable map because it can contain
the values themselves.

## Runtime configuration

Configure the Amplify main-branch build with public values only:

```text
NEXT_PUBLIC_SELF_ENDPOINT=https://proofofhumanity.org/api/self-verify
NEXT_PUBLIC_SELF_ENV=staging
POH_QUICK_LAUNCH_API_ORIGIN=https://<dedicated-host>
```

Configure the dedicated single-task API service with:

```text
POH_API_RUNTIME=dedicated-single-replica
POH_BLOCKCHAIN_TRANSACTIONS_ENABLED=false
POH_SOURCE_REVISION=<40 lowercase hex>
NEXT_PUBLIC_SELF_ENDPOINT=https://proofofhumanity.org/api/self-verify
NEXT_PUBLIC_SELF_ENV=staging
POH_RUNTIME_TOPOLOGY=single-sticky-node
POH_TOPOLOGY_ATTESTATION_SHA256=<64 lowercase hex>
POH_ISSUER_SECRET_ATTESTATION_SHA256=<64 lowercase hex>
POH_SPONSOR_SECRET_ATTESTATION_SHA256=<64 lowercase hex>
POH_SPONSOR_TESTNET_CHAIN_IDS=84532
```

`ISSUER_PRIVATE_KEY` and `POH_SPONSOR_PRIVATE_KEY` must be injected from their approved paths. If the
runtime does not receive a provider revision variable, `POH_SOURCE_REVISION` must remain the exact
40-hex main commit. Neither key, either secret reference, signer attestation, topology attestation or
API runtime variable belongs in Amplify. Do not set any readiness variable on a preview branch or a
multi-instance/serverless deployment. Restart the candidate after configuration and retain the
redacted provider change record.

`GET /api/quick-launch-readiness` through the canonical domain is proxied to the dedicated service and
returns only public facts: release/chain, source revision, attestation
digests, derived signer addresses, sponsor allowlist and blocker codes. It never signs, reads chain
state, returns a key, returns a raw secret reference, or sends a transaction. It responds `503` until
all runtime facts pass, and uses `Cache-Control: no-store`. Schema version 2 additionally requires the
dedicated runtime declaration and proves the blockchain transaction flag is off.

## External verification and evidence

First run the contract/callback preflight:

```sh
NEXT_PUBLIC_SELF_ENDPOINT=https://proofofhumanity.org/api/self-verify \
  pnpm --filter @ubi2/proofofhumanity quick-launch:preflight
```

Then run the host preflight from outside the deployment. Supply only public hashes and the public
revision; do not source a deployment environment file:

```sh
QUICK_LAUNCH_EXPECTED_SOURCE_REVISION=<40 lowercase hex> \
QUICK_LAUNCH_EXPECTED_TOPOLOGY_ATTESTATION_SHA256=<64 lowercase hex> \
QUICK_LAUNCH_EXPECTED_ISSUER_SECRET_ATTESTATION_SHA256=<64 lowercase hex> \
QUICK_LAUNCH_EXPECTED_SPONSOR_SECRET_ATTESTATION_SHA256=<64 lowercase hex> \
  pnpm --filter @ubi2/proofofhumanity quick-launch:host-preflight
```

The command performs HTTPS reads only. It verifies the Quick Launch/Base Sepolia page markers, absence
of non-release testnet selectors, deleted demo route, exact runtime revision, exact attestation hashes,
expected issuer, distinct sponsor and exact sponsor allowlist. Its allowlisted JSON output is safe to
archive. Any missing input, HTTP mismatch, unknown response field, runtime blocker, hash mismatch or
role overlap exits nonzero.

## Current blocker checklist (2026-08-30)

- [x] Merged Quick Launch UI is publicly observable on `proofofhumanity.org`.
- [x] Transaction-free Base Sepolia contract/callback preflight is green.
- [x] Deleted demo-credential route returns `404`.
- [ ] Billable dedicated-origin stack approved and provisioned from the digest-pinned image.
- [ ] Deployment-owner access capable of proving the ECS desired/running/pending counts and
      stop-before-start deployment policy. CloudFront headers do not establish a sticky Node process.
- [ ] Immutable topology attestation URL/path and SHA-256.
- [ ] Approved issuer secret-manager reference and immutable redacted injection-attestation SHA-256.
- [ ] Approved sponsor secret-manager reference, public sponsor address and immutable redacted
      injection-attestation SHA-256.
- [ ] Runtime source revision visible through `POH_SOURCE_REVISION`.
- [ ] Direct-origin restart/redaction evidence passes with a changed boot ID and no task overlap.
- [ ] Amplify contains only the public API origin/callback configuration and proxies the exact four paths.
- [ ] Merged readiness endpoint returns `200` with `ready: true` and all external hashes match.

Until every unchecked item passes, do not run Self on a phone, fund a sponsor, send a transaction or
call the automatically deployed origin a sticky-node release candidate.
