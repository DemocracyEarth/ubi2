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
overwrite an existing file and still writes a blocked observation before exiting `2`:

```shell
pnpm --filter @ubi2/status-operator start -- fleet \
  --config /etc/ubi2/status-operator/fleet.json \
  --evidence /var/lib/ubi2-status-evidence/2026-08-16T210000Z-baseline.json

pnpm --filter @ubi2/status-operator start -- verify-evidence \
  --input /var/lib/ubi2-status-evidence/2026-08-16T210000Z-baseline.json
```

Evidence contains public trust metadata, health, signed artifacts, immutable cache metadata, the third-RPC
finalized header, and the reproduced fleet report. RPC URLs are deliberately excluded because their paths may be
service credentials. Verification recomputes the checksum, signatures, immutable equality, freshness, quorum and
publication decision offline. The bundle is not a trust anchor: compare its public fleet metadata and SHA-256 to
the independently reviewed deployment record before using it as transaction evidence.

See [`ops/status-operator`](../../ops/status-operator) for strict configuration examples, systemd units, key
isolation and the canonical-testnet evidence checklist.
