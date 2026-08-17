# Canonical-testnet packed-status operations runbook

This runbook turns the packed-status operator package into reproducible operational evidence on one explicitly
selected canonical **testnet**. It does not authorize a mainnet deployment, a status publication transaction, or a
claim that a drill passed. A run is successful only when the observed bundles, service results and external page
acknowledgements exist.

## Required topology and public trust record

Use three independent trust paths:

| Role | Required isolation |
| --- | --- |
| `reconciler-a` | Host A, volume A, RPC provider A, encrypted keystore A and password-file A |
| `reconciler-b` | Host B, volume B, RPC provider B, encrypted keystore B and password-file B |
| fleet gate | Monitoring host C, RPC provider C, the two public HTTPS artifact origins and a real paging route |

Before provisioning, record the selected testnet name and chain ID, issuance-registry address, issuer key ID,
registry deployment transaction, public deployer, current owner, on-chain status publisher, reconciler signer
addresses, reviewed source commit, executable SHA-256 values, three provider names and three host/volume IDs. Never
record RPC project URLs, private keys, passwords, seed phrases or environment-file contents in the evidence store.
Use the strict [`trust-record.example.json`](trust-record.example.json) schema, add the independently reviewed
registry runtime code hash, replace every fixture value, and keep the completed record under change control.

The deployment helper currently permits only Base Sepolia `84532`, Ethereum Sepolia `11155111`, Celo Sepolia
`11142220`, Robinhood Chain Testnet `46630`, and World Chain Sepolia `4801`. The release lane must name exactly one
as the canonical issuance testnet. Any other chain ID, including every mainnet, is a stop condition.

## Transaction-free trust preflight

From a controlled administration host, first bind the public trust record to both operator configs and the fleet
config and capture one non-overwriting preflight observation:

```shell
PREFLIGHT_EVIDENCE=/var/lib/ubi2-status-evidence/canonical-testnet/preflight-YYYYMMDDTHHMMSSZ.json

pnpm --filter @ubi2/status-operator start -- preflight \
  --trust-record /etc/ubi2/status-operator/canonical-testnet-trust.json \
  --operator-a /etc/ubi2/status-operator/reconciler-a.json \
  --operator-b /etc/ubi2/status-operator/reconciler-b.json \
  --fleet /etc/ubi2/status-operator/fleet.json \
  --evidence "$PREFLIGHT_EVIDENCE"

pnpm --filter @ubi2/status-operator start -- verify-preflight \
  --input "$PREFLIGHT_EVIDENCE" \
  --trust-record /etc/ubi2/status-operator/canonical-testnet-trust.json \
  --operator-a /etc/ubi2/status-operator/reconciler-a.json \
  --operator-b /etc/ubi2/status-operator/reconciler-b.json \
  --fleet /etc/ubi2/status-operator/fleet.json
```

The capture uses each provider's `finalized` block and requires all three paths to agree on the reviewed registry
bytecode, successful direct deployment, the recorded owner with no pending transfer, issuance domain, active issuer key and active
status publisher/codehash. It also rejects reused RPC URLs, provider labels, hosts, volumes, signers or origins and
requires the operator executable hashes to match the trust record. It never initializes a signer or submits a
transaction. A blocked network observation is still written and exits `2`; the evidence contains no RPC URL,
secret path or provider error text.

The report always lists four facts that remain externally observed: actual host/volume/provider independence,
on-host source/executable hashes, encrypted-keystore public-address/file-permission checks, and an authoritative
archive timestamp. Do not mark those complete from the JSON alone.

The following commands are the independent human spot-check and incident fallback. Run them separately against
providers A, B and C before starting an operator and again before any publication simulation. Load RPC URLs from
the host secret manager without printing them. Replace only the public placeholders below; do not paste a secret
into the command history.

```shell
test "$(cast chain-id --rpc-url "$RPC_URL")" = "$EXPECTED_TESTNET_CHAIN_ID"
test "$(cast code "$ISSUANCE_REGISTRY" --rpc-url "$RPC_URL")" != "0x"

cast call "$ISSUANCE_REGISTRY" 'owner()(address)' --rpc-url "$RPC_URL"
cast call "$ISSUANCE_REGISTRY" 'issuanceDomain()(bytes32)' --rpc-url "$RPC_URL"
cast call "$ISSUANCE_REGISTRY" \
  'issuerKeys(bytes32)(bool,bool,uint64)' "$ISSUER_KEY_ID" --rpc-url "$RPC_URL"
cast call "$ISSUANCE_REGISTRY" \
  'statusPublishers(bytes32,address)(bytes32,bool,bool)' \
  "$ISSUER_KEY_ID" "$STATUS_PUBLISHER" --rpc-url "$RPC_URL"
cast tx "$REGISTRY_DEPLOYMENT_TX" --rpc-url "$RPC_URL"
cast receipt "$REGISTRY_DEPLOYMENT_TX" --rpc-url "$RPC_URL"
```

All three providers must return the selected chain ID, deployed registry bytecode, the same issuance domain, an
active registered issuer key, and an active registered publisher. The transaction sender must equal the recorded
public deployer; its successful receipt must create the recorded registry. The current owner must equal the
recorded intended testnet owner. Stop on any mismatch. These are read-only calls; they do not authorize a
transaction.

On each operator host, verify only the public address of the encrypted keystore and compare it to both the local
operator config and the fleet config:

```shell
cast wallet address --keystore "$KEYSTORE_PATH" --password-file "$PASSWORD_FILE"
```

Do not use `set -x`, print an environment file, or copy either secret file into the evidence directory.

## Host installation

Build the reviewed commit and pin both executable hashes exactly as described in [`README.md`](README.md). Copy
`operator.example.json` separately for `reconciler-a` and `reconciler-b`; change every fixture value. The two files
must agree on chain ID, registry and issuer key, but must use different operator IDs, RPC providers, signers,
keystores, password files, state volumes and public origins. Both hosts start from one manually reviewed identical
checkpoint.

Install and start the operator service on its corresponding host:

```shell
systemctl enable --now ubi2-status-operator@reconciler-a.service
systemctl is-active ubi2-status-operator@reconciler-a.service
curl --fail --silent http://127.0.0.1:8787/readyz
```

Use `reconciler-b` and its configured loopback port on Host B. Terminate TLS at separate reverse proxies. Expose
only `/healthz`, `/readyz`, `/latest`, and `/artifacts/0x<snapshotHash>`. Do not expose the state directory.

On Host C, install `fleet.json` with provider C and the two HTTPS origins, then enable the timer:

```shell
systemctl enable --now ubi2-status-fleet@canonical-testnet.timer
systemctl list-timers ubi2-status-fleet@canonical-testnet.timer
```

Wire `ubi2-status-fleet@canonical-testnet.service` failure to the existing production paging connector with a
systemd `OnFailure=` drop-in. The paging unit must not put a webhook credential on its command line. Confirm the
resolved unit rather than assuming the drop-in loaded:

```shell
systemctl daemon-reload
systemctl show ubi2-status-fleet@canonical-testnet.service -p OnFailure
```

An empty `OnFailure`, an unowned test notification, or a journald-only alarm blocks the canonical-testnet claim.

## Capturing and verifying evidence

Create a new filename for every observation. The CLI uses an atomic hard-link publication and refuses to overwrite
prior evidence. It writes a valid blocked observation before returning exit `2`, which is required for drills.

```shell
EVIDENCE_ROOT=/var/lib/ubi2-status-evidence/canonical-testnet
EVIDENCE_PATH="$EVIDENCE_ROOT/$(date -u +%Y%m%dT%H%M%SZ)-baseline.json"

pnpm --filter @ubi2/status-operator start -- fleet \
  --config /etc/ubi2/status-operator/fleet.json \
  --evidence "$EVIDENCE_PATH"

pnpm --filter @ubi2/status-operator start -- verify-evidence \
  --input "$EVIDENCE_PATH" \
  --config /etc/ubi2/status-operator/fleet.json
```

`ready: true` means the two live `/latest` documents matched their content-addressed immutable endpoints, both
signatures and configured identities were valid, the third-RPC finalized header was compatible, and the quorum
produced publication arguments. The evidence verifier recomputes that decision offline and requires its public
fleet metadata to equal the separately supplied fleet config. It does not prove that a page reached a human or
that a later publication transaction used those arguments. First compare the supplied config's chain, registry,
issuer key, operator origins and signer addresses to the independently reviewed public trust record, then record
the bundle SHA-256 there.

Archive beside each bundle: source commit, systemd unit hashes, executable hashes, host/volume/provider IDs, and—if
a transaction is separately authorized—the simulation plus final receipt. Keep the external paging incident ID
and acknowledgement timestamp in the operational incident system; do not invent them in repository documentation.

## Required drills

Run each drill on the selected testnet. Never change a live keystore, manually edit operator state, or publish a
root during a drill.

### Restart recovery

1. Capture and verify a ready baseline.
2. Restart Host A's operator with `systemctl restart ubi2-status-operator@reconciler-a.service`.
3. Confirm exactly one writer, a healthy `/readyz`, and no automatic deletion of `operator.lock` after an unclean
   stop. If a stale lock exists, inspect the process and volume before a human removes it.
4. Capture and verify a second ready bundle. The checkpoint may advance, but it must not regress or equivocate.
5. Repeat on Host B. Record service results and restart timestamps beside the bundles.

### Publication withholding

1. Capture and verify a ready baseline.
2. In the approved testnet drill window, stop Host B's reverse proxy while keeping the reviewed origin and fleet
   config unchanged. Do not alter the signed files and do not point the on-chain publisher at drill output.
3. Run the canonical fleet config. Once the endpoint is unavailable or provider C advances beyond `maxBlockLag`,
   capture the blocked report. It must contain `WITHHOLDING_SUSPECTED`, `HEARTBEAT_STALE`, or
   `OPERATOR_UNAVAILABLE`, and `publication` must be `null`.
4. Confirm the real paging connector produced an incident and a human acknowledged it.
5. Restore the canonical origin, capture a new ready bundle, and close the incident only after recovery is
   observed.

### Divergence

Never manufacture a divergent root with a live reconciler key. Exercise the same-height hash branch on a disposable
testnet fork or isolated RPC fault proxy used only by a temporary Host C fleet config. When the third-RPC finalized
hash conflicts with the signed operator view, capture `SNAPSHOT_DIVERGENCE`, a null publication, the external page
and the subsequent ready recovery bundle. The repository test suite separately proves that two differently signed
roots at the same source block also fail closed.

## Offline drill-evidence gate

After all observations are captured, copy [`drill-manifest.example.json`](drill-manifest.example.json) into the
evidence directory and replace every path with the corresponding immutable bundle. The manifest must contain one
restart pair for every operator in the reviewed fleet config and distinct before/blocked/after files for each fault:

```shell
pnpm --filter @ubi2/status-operator start -- verify-drill-evidence \
  --manifest /var/lib/ubi2-status-evidence/canonical-testnet/drill-manifest.json \
  --config /etc/ubi2/status-operator/fleet.json
```

`intrinsicEvidenceValid: true` means every bundle passed checksum, signature, immutable-artifact, fleet-decision
and reviewed-config binding; embedded restart/recovery observation times are ordered and the snapshots cannot
regress or equivocate; withholding contains an allowed fail-closed alert; and divergence contains
`SNAPSHOT_DIVERGENCE`. It is not a completed-drill claim. The report always returns six
`externalChecksRequired` values covering authoritative archive timestamps, restart service results/single-writer
inspection, the withholding action, divergence fault isolation, and real withholding/divergence page
acknowledgements. Attach those records from their authoritative systems before checking any completion item.

## Canonical-testnet completion checklist

- [ ] One permitted testnet is explicitly selected; chain ID, registry, deployment transaction and public deployer
      agree through providers A, B and C.
- [ ] A non-overwriting `ready: true` preflight evidence file verifies offline against the reviewed trust record,
      both operator configs and the fleet config; its SHA-256 and authoritative capture time are externally anchored.
- [ ] Registry owner, issuance domain, active issuer key and active separate status publisher agree through all
      three providers.
- [ ] Two hosts, volumes, RPC providers, reconciler signers, encrypted keystores and password-file paths are
      independently provisioned.
- [ ] Two separate HTTPS origins serve immutable artifacts and pass a ready evidence capture.
- [ ] Fleet provider C is independent; the systemd timer is active.
- [ ] A real paging connector is wired, fires on exit `2`, and has an observed acknowledgement.
- [ ] Restart, publication-withholding and divergence bundles verify offline; recovery bundles are ready.
- [ ] Every bundle SHA-256 and capture time is anchored in the independent evidence store or incident system.
- [ ] No root publication is claimed without its reviewed evidence, separate simulation and observed receipt.

If any item is missing, report it as a blocker. Committed templates, local tests, screenshots, or an unacknowledged
log line do not satisfy this checklist.
