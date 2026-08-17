# `@ubi2/status-operator`

Composable testnet operator for v2 packed-status checkpoints. The package deliberately separates four trust
decisions so deployments and tests can replace them independently:

1. `ZkIdentityFinalizedRpcReader` obtains the bounded finalized allocation transcript.
2. `ZkIdentityPackedStatusBuilder` restores and advances the Poseidon tree. The production adapter invokes the
   SHA-256-pinned Rust binary with `execFile`; it never opens a shell.
3. `ZkIdentityStatusDigestSigner` signs the already-derived EIP-712 digest without a personal-message prefix. The
   production adapter accepts only an encrypted Foundry keystore plus a separate password-file path.
4. `ZkIdentityStatusOperatorStore` publishes the signed artifact and replay checkpoint through atomic rename and
   directory fsync.

`runZkIdentityStatusOperatorCycle` returns a closed set of public error codes and never returns provider or signer
error text. A failed cycle keeps the last signed artifact, writes degraded health when storage is available, and
never derives publisher calldata.

`evaluateZkIdentityStatusOperatorFleet` is a separate consumer. Give it strict fleet configuration, both untrusted
operator documents, their content-addressed immutable artifacts, and the finalized header from a third RPC. It
validates every envelope and signer, requires `/latest` to equal the immutable artifact byte-for-byte after
canonical parsing, detects staleness/lag/split views, calls the SDK threshold reconciler, and returns `publication`
only when `ready` is true. Do not construct calldata from `/latest` directly.

```ts
const report = await evaluateZkIdentityStatusOperatorFleet({
  config,
  fetched: [operatorA, operatorB],
  referenceFinalizedBlock,
});

if (!report.ready) throw new Error("packed-status publication blocked");
// report.publication is now normalized for ZkIdentityIssuanceRegistry.
```

The CLI can atomically archive a secretless evidence bundle while running the live fleet gate. It refuses to
overwrite an existing file and still writes a blocked observation before exiting `2`. Both operator and fleet CLI
commands reject every chain ID before initializing a signer or network reader except Base Sepolia `84532`,
Ethereum Sepolia `11155111`, Celo Sepolia `11142220`, Robinhood Chain Testnet `46630`, and World Chain Sepolia
`4801`:

```shell
pnpm --filter @ubi2/status-operator start -- fleet \
  --config /etc/ubi2/status-operator/fleet.json \
  --evidence /var/lib/ubi2-status-evidence/2026-08-16T210000Z-baseline.json

pnpm --filter @ubi2/status-operator start -- verify-evidence \
  --input /var/lib/ubi2-status-evidence/2026-08-16T210000Z-baseline.json \
  --config /etc/ubi2/status-operator/fleet.json
```

Evidence contains public trust metadata, health, signed artifacts, immutable cache metadata, the third-RPC
finalized header, and the reproduced fleet report. RPC URLs are deliberately excluded because their paths may be
service credentials. Verification recomputes the checksum, signatures, immutable equality, freshness, quorum and
publication decision offline, then requires its public chain, registry, issuer, thresholds, operator origins and
signers to equal the independently supplied fleet config. The bundle is not a trust anchor: the supplied config
must first be compared to the independently reviewed deployment record.

After capturing each ready/blocked/recovery observation in the runbook, put only their absolute paths in a strict
drill manifest and verify the intrinsic relationships offline:

```shell
pnpm --filter @ubi2/status-operator start -- verify-drill-evidence \
  --manifest /var/lib/ubi2-status-evidence/canonical-testnet/drill-manifest.json \
  --config /etc/ubi2/status-operator/fleet.json
```

This gate requires a chronological non-regressing ready transition for every configured operator restart, an
allowed fail-closed withholding alert, an exact `SNAPSHOT_DIVERGENCE` alert and ready recovery observations. Its
report always lists authoritative archive timestamps, service results, single-writer inspection, fault isolation
and real page acknowledgements as external checks: an offline manifest cannot prove those events happened or that
its internally checksummed observation times equal wall-clock capture time.

See [`ops/status-operator`](../../ops/status-operator) for strict configuration examples, systemd units, key
isolation and the canonical-testnet evidence checklist.
