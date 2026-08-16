# Packed-status operator deployment

This directory deploys the v2 packed-status reference operator as two independent, read-only artifact services and
one fleet check. It is suitable for a canonical **testnet** rehearsal. It does not authorize mainnet publication.

## Trust and isolation

Run `reconciler-a` and `reconciler-b` on different hosts, storage volumes, RPC providers and encrypted EOA
keystores. Do not share either reconciler key with the Self verification authority, deployment account, on-chain
status publisher, fleet checker or reverse proxy. The fleet checker uses a third independently configured RPC.

The daemon:

- reads only the RPC `finalized` range and caps a cycle at 512 blocks;
- invokes the prebuilt Rust snapshot binary with fixed arguments and no shell;
- signs only the exact EIP-712 digest through `cast --keystore ... --password-file ... --no-hash`;
- verifies the configured SHA-256 of both executables before every invocation;
- fsyncs immutable signed artifacts, `latest.json`, and the replay checkpoint before reporting health;
- refuses checkpoint regression/equivocation and a second writer in the same state directory;
- binds its HTTP server to loopback and exposes only `GET /healthz`, `/readyz`, `/latest`, and
  `/artifacts/0x<snapshotHash>`.

The health document is operational metadata, not a publication authorization. The fleet checker independently
recovers both artifact signers and reconciles the signed snapshot content before returning publication arguments.
Terminate TLS at a reverse proxy and allow only those four read routes. Never expose the state directory.
The reference fleet fetch caps each JSON response at 2 MiB; exceeding that limit blocks publication. Production
retention, chunking/CDN transport and larger-population artifact limits remain a later measured design decision.

## Host preparation

Build from the reviewed commit on each host:

```shell
pnpm install --frozen-lockfile
pnpm --filter @ubi2/status-operator build
cargo build --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked
shasum -a 256 tools/v2-crypto-bench/target/release/ubi2-v2-crypto-bench
shasum -a 256 /usr/local/bin/cast
```

Create a dedicated unprivileged `ubi2-status` user. Provision these files outside the repository:

- `/etc/ubi2/status-operator/reconciler-a.json` or `reconciler-b.json`, mode `0600`;
- one Foundry encrypted JSON keystore, mode `0600`;
- its separate password file, mode `0600`;
- a manually reviewed initial checkpoint copied identically to both hosts.

Import each EOA interactively; do not pass a private key or password on the command line:

```shell
cast wallet import reconciler-a --interactive --keystore-dir /etc/ubi2/status-operator/keystores
```

Create the password file through the host secret manager or an interactive root-only editor, then verify the public
address with `cast wallet address --keystore PATH --password-file PATH`. Put only that public address in the operator
and fleet configs. The daemon rejects secret files accessible to group or other users and never accepts a raw key
environment variable.

Copy [`operator.example.json`](operator.example.json), replace every fixture value, and install
[`ubi2-status-operator@.service`](ubi2-status-operator@.service). The config `stateDirectory` must match the
instance name created by `StateDirectory` in the unit. A crash can leave `operator.lock`; inspect the process and
state volume before manually removing it. Never delete it automatically.

Prefix the two reviewed `shasum` outputs with `0x` and pin them in `builderSha256` and `castSha256`. Adjust the
absolute `ExecStart` paths in the templates to the host's reviewed Node/pnpm installation. Encrypted local keystores
are a testnet mechanism, not a mainnet custody recommendation; production signing still requires the audited HSM or
remote-signer work and its own availability/recovery drill.

## Independent fleet gate

Install [`fleet.example.json`](fleet.example.json) only on a third monitoring host. Its two `baseUrl` values must be
independent HTTPS origins and `referenceRpcUrl` must not be either operator's RPC. Run:

```shell
pnpm --filter @ubi2/status-operator start -- fleet --config /etc/ubi2/status-operator/fleet.json
```

Exit `0` means every configured operator is available, fresh, within the finalized-block lag budget, byte-identical
at quorum, and signed by its pinned EOA. Exit `2` means publication is blocked and the JSON report contains only
machine-readable alert codes. Missing reference RPC, stale heartbeat, degraded operator, withholding, split root,
wrong signer, malformed content and unavailable quorum all fail closed. Route failed systemd units or exit `2` to
the production paging system; journald alone is not a page.

Before a testnet checkpoint transaction, archive the two immutable artifact URLs, fleet report, reference finalized
block, transaction simulation and final receipt. The on-chain publisher must consume only the fleet report's
`publication` fields and must remain a separate key path.
