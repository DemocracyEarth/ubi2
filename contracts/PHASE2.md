# Proof of Humanity Phase 2 — testnet dry-run

Phase 2 deploys the production contract stack to supported **testnets only**, verifies the source, and
runs one encrypted-keystore-signed mint on each deployment. Nothing in these helpers accepts a mainnet
chain ID or a raw private-key environment variable.

## Supported networks

| Name | Chain ID | Gas | RPC variable | Explorer |
| --- | ---: | --- | --- | --- |
| Base Sepolia | 84532 | test ETH | `BASE_SEPOLIA_RPC_URL` | `https://sepolia-explorer.base.org` |
| Ethereum Sepolia | 11155111 | test ETH | `ETHEREUM_SEPOLIA_RPC_URL` | `https://sepolia.etherscan.io` |
| Celo Sepolia | 11142220 | test CELO | `CELO_SEPOLIA_RPC_URL` | `https://celo-sepolia.blockscout.com` |
| Robinhood Chain Testnet | 46630 | test ETH | `ROBINHOOD_TESTNET_RPC_URL` | `https://explorer.testnet.chain.robinhood.com` |
| World Chain Sepolia | 4801 | test ETH | `WORLDCHAIN_TESTNET_RPC_URL` | `https://sepolia.worldscan.org` |

The public addresses, deployment transactions, verification status, and live probe transactions are
recorded in [`DEPLOYMENTS.md`](DEPLOYMENTS.md). That registry is the source of truth used to wire the
website; local Foundry broadcast manifests remain untracked release evidence.

The original release brief named Celo Alfajores (`44787`). Alfajores reached end-of-life on
2025-09-30 and was replaced by Celo Sepolia, so the wrapper intentionally refuses Alfajores. The
network values above come from the current [Celo](https://docs.celo.org/build-on-celo/network-overview),
[Robinhood Chain](https://docs.robinhood.com/chain/connecting/), and
[World Chain](https://docs.world.org/world-chain/quick-start/info) documentation.

## 1. Create or import disposable encrypted keystores

Run these commands yourself. Never paste a private key into chat or put one in an env file.

```shell
cast wallet import poh-testnet-deployer --interactive
cast wallet import poh-testnet-issuer --interactive
```

Use separate deployer and issuer accounts. Fund only the deployer with faucet tokens on each testnet.
The issuer signs the e2e voucher but needs no gas.

Record only the public addresses:

```shell
cast wallet address --account poh-testnet-deployer
cast wallet address --account poh-testnet-issuer
```

## 2. Configure addresses, RPCs, and verification

```shell
cp phase2.env.example .env.phase2
```

Fill `.env.phase2` locally. `POH_ISSUER` must equal the address of `poh-testnet-issuer`. `POH_OWNER`
may be the testnet deployer for the dry-run; production requires the intended multisig. RPC URLs and
explorer API keys are service credentials, so keep them out of logs and commits.

For non-interactive release automation, set `DEPLOYER_PASSWORD_FILE` and `ISSUER_PASSWORD_FILE` to
separate mode-`0600` files outside the repository. Put only the file paths in `.env.phase2`; never put
the passwords themselves there. If both keystores intentionally use one password,
`WALLET_PASSWORD_FILE` remains available as a common fallback. The wrapper refuses password files
whose permissions are broader than `0400` or `0600`.

Load the file without printing it:

```shell
set -a
source .env.phase2
set +a
```

## 3. Preflight and simulate

Run both commands for each supported network:

```shell
./scripts/phase2.sh preflight base-sepolia
./scripts/phase2.sh simulate base-sepolia
```

Preflight verifies the exact RPC chain ID, nonzero owner/issuer addresses, issuer-keystore match,
deployer balance, predicate enablement, and a clean git worktree. Simulation runs `Deploy.s.sol`
without `--broadcast` or `--verify`. Public JSON files produced by prior `Deploy.s.sol` runs under
`contracts/broadcast/` are the only untracked files the clean-tree check permits.

To run either non-broadcast gate across every testnet and receive one failure summary:

```shell
./scripts/phase2-all.sh preflight
./scripts/phase2-all.sh simulate
```

The aggregate helper deliberately refuses `deploy`; each broadcast keeps the explicit confirmation
shown below.

## 4. Broadcast and verify after reviewing the simulation

Broadcast requires a second, network-specific confirmation. This is intentionally verbose so a stale
shell variable cannot authorize another chain.

```shell
export PHASE2_BROADCAST_CONFIRM=base-sepolia:84532
./scripts/phase2.sh deploy base-sepolia
unset PHASE2_BROADCAST_CONFIRM
```

The script deploys only `PoHCardRenderer`, `ProofOfHumanity`, and `PredicateVerifier`, uses `--slow`,
submits source verification, and validates Foundry's broadcast manifest. A manifest containing the
demo-only `SybilResistantVote` is rejected.

## 5. Run the on-chain e2e mint

```shell
./scripts/phase2.sh e2e base-sepolia
```

The e2e command reads the deployed addresses from Foundry's broadcast manifest and then:

- verifies `ProofOfHumanity` owner, issuer, renderer, and deployed bytecode;
- verifies `PredicateVerifier` owner/issuer and that `prover()` is zero;
- obtains the chain-specific voucher digest from `hashVoucher`;
- signs that digest through `cast wallet sign --account poh-testnet-issuer`;
- mints through the deployer, then asserts ownership, `isValid`, and `locked`;
- asserts voucher replay and ERC-721 transfer both revert.
- signs and checks an `age>=18` predicate against the live verifier, then asserts a wrong-subject
  presentation reverts without disclosing the underlying age.

The default deterministic probe is safe to rerun: while its existing token remains valid, the script
revalidates that token and the negative cases without minting again. Set `PHASE2_E2E_RUN_ID` to a
non-secret unique label only when a genuinely new probe token is required.

It prints only public addresses, transaction hashes, and assertion results.

Repeat preflight → simulate → explicit deploy → e2e for:

```text
base-sepolia
ethereum-sepolia
celo-sepolia
robinhood-testnet
worldchain-sepolia
```

Once all deployments exist, the repeatable aggregate live gate is:

```shell
./scripts/phase2-all.sh e2e
```

After each chain, confirm all three contracts show verified source in the explorer and record contract
addresses plus deployment/mint transaction hashes in `DEPLOYMENTS.md`. Do not proceed to any mainnet
until all five transcripts are green and the human separately approves that mainnet chain.

## 6. Separate v2 Self issuance rehearsal

The portable v2 credential uses one canonical issuance chain, not one registry on every presentation
chain. Its pre-deployment rehearsal is deliberately separate from `phase2.sh` and is not included in
`phase2-all.sh`. Select one supported testnet first, create isolated encrypted verification-authority and
status-publisher accounts, and keep only their public addresses in `.env.phase2`:

```shell
cast wallet import poh-v2-self-authority --interactive
cast wallet address --account poh-v2-self-authority
cast wallet import poh-v2-status-publisher --interactive
cast wallet address --account poh-v2-status-publisher
```

Compute `ZK_SELF_CONFIG_ID` with the SDK's `zkSelfVerifierConfigId(...)` from the exact public Self
scope, callback endpoint, `staging`/`production` environment, e-passport attestation id `1`, and
`@selfxyz/core@1.0.8`. Record the bytes32 issuer namespace in `ZK_ISSUER_KEY_ID`, the isolated public
address in `ZK_SELF_VERIFICATION_AUTHORITY`, and the intended registry owner in `ZK_ISSUANCE_OWNER`.
Record the separate publisher address in `ZK_STATUS_PUBLISHER`; it will later authenticate allocation-bound
packed-status checkpoints and must not share the verification authority's production key path.
Before any checkpoint transaction, two independently configured operators must ingest only their independently
configured RPC's `finalized` range with `collectZkIdentityFinalizedStatusTranscript`, advance and durably store the
deterministic checkpoint with `--advance-status-snapshot`, then sign its exact SDK content hash using
`zkIdentityPackedStatusAttestationTypedData`. The publication process must call
`reconcileZkIdentityPackedStatusSnapshots` with trusted reconciler addresses and use only the returned
`reconciledZkIdentityStatusPublication` arguments. The on-chain publisher key is separate from both reconcilers.
The current SDK recovers 65-byte ECDSA signatures from EOA reconcilers; ERC-1271 contract-wallet validation is a
separate production hardening item.
The deployable reference daemon and fleet gate live in `packages/status-operator` and `ops/status-operator`. They
must still be installed on independent hosts, connected to real paging and exercised through restart, withholding
and divergence drills. Committed templates are not evidence that this happened and do not authorize mainnet.
Then simulate before the explicitly reviewed broadcast:

```shell
forge script script/DeployZkSelfIssuance.s.sol:DeployZkSelfIssuance \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" --account poh-testnet-deployer

forge script script/DeployZkSelfIssuance.s.sol:DeployZkSelfIssuance \
  --rpc-url "$BASE_SEPOLIA_RPC_URL" --account poh-testnet-deployer --broadcast --verify
```

The script refuses every mainnet chain id. It deploys the registry and immutable bridge, registers the
issuer key, pins the bridge and status-publisher codehashes, and initiates two-step ownership transfer. A different final owner
must call `acceptOwnership` separately. Before enabling the web callback, record and verify both
contracts, accept ownership, configure all six server-only `ZK_SELF_ISSUANCE_*` variables, and capture
one live issuance plus one duplicate-passport rejection. The verification authority needs no gas; the status
publisher needs gas only when a reviewed checkpoint is published. Neither private key may enter this deployment
environment.
