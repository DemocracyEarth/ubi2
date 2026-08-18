# V2 production-profile admission gate

- **Status:** release gate implemented; no production profile is approved by this document
- **Owner:** release/integration lead; inputs supplied by circuit, holder, operations and independent reviewers
- **SDK:** [`zk-production-profile.ts`](../../packages/sdk/src/zk-production-profile.ts)
- **Live preflight:** [`zk-production-profile-cli.ts`](../../packages/sdk/src/zk-production-profile-cli.ts)
- **Parent decisions:** [ADR-0012](adr/0012-v2-cross-lane-interface-freeze.md) and
  [V2 identity](10-evm-zk-identity-v2.md)

## Purpose

The repository has reproducible research circuits and a pre-deployment governance registry, but those facts do
not authorize production. The deterministic research setup exposes its toxic waste, local gas is not target-chain
evidence, and a structurally valid verifier can still be deployed behind the wrong governance or adapter.

This gate is the release-owned boundary between reviewed artifacts and activation. It validates a versioned,
content-addressed profile; matches it to exact runtime bytecode on one chain; verifies timelocked ownership and
inactive on-chain state; and emits the exact governance calldata. It has no signer, keystore or broadcast path.

No production manifest is checked in yet. ADR-0013 now supplies implementation-ratified cryptographic parameters,
content-addressed vectors and the exact manifest-input checklist, but it does not supply ceremony keys, independent
audits, device evidence or live target identities. Research circuit identifiers, public-toxic-waste verifier
artifacts and the five existing v1-only Phase 2 hosts remain inadmissible.

## Manifest V1

The canonical runtime schema is `org.proofofhumanity.zk-production-profile/1`. Parsing is strict: missing fields,
unknown fields, non-canonical values and a mismatched self-hash fail closed. The manifest's `manifestHash` is the
Keccak-256 of canonical key-sorted JSON excluding `manifestHash` itself.

| Section | Required binding |
|---|---|
| release | candidate/approved state, canonical approval time, full source commit |
| circuit | circuit ID/name, frozen 18-signal layout, proof system, commitment, issuer authentication, status tree and compiler versions |
| issuers | sorted unique nonzero issuer key identifiers |
| artifacts | parameter manifest, circuit source, constraint system, compiler lock, prover/verifier artifacts, verifier source and public-signal manifest |
| setup | proof-system-appropriate provenance plus independent reproduction |
| audits | circuit, cryptography, Solidity, privacy, QA, reliability, security and accepted-risk reports; open Critical/High counts |
| device evidence | representative platform/browser sample count, p95 proof time, peak memory and content-addressed report |
| target evidence | exact chain/deployment addresses and runtime codehashes, block/gas budget, gas report and integration report |

Every evidence reference uses HTTPS or IPFS and includes a nonzero SHA-256 content digest. The digest, not a
mutable filename, is the reviewed identity. Release reviewers must independently retrieve and hash the evidence;
the live RPC preflight deliberately does not download arbitrary manifest URLs.

### Setup-specific requirements

- `circuit-specific-mpc`: Phase 1 and Phase 2 transcripts, at least three contributions, a final beacon,
  contribution-verification report and independent reproduction.
- `universal-updatable`: universal SRS, at least one recorded contribution, contribution verification and
  independent reproduction.
- `transparent`: setup rationale and independent reproduction; contribution count must be zero.

ADR-0013 selects circuit-specific Groth16/BN254 for V2 profile 1. This section records the evidence that selection
must produce per circuit; it does not allow a suite-selection manifest to stand in for a verified ceremony.

## Admission invariants

`admitZkProductionProfile` accepts only `production-approved` manifests and requires:

1. zero open Critical and High findings;
2. at least one `mid-range-mobile` benchmark with at least 20 samples;
3. no research, fixture, testnet, localhost or `.invalid` identifier/evidence reference;
4. rejection of the two known deterministic research circuit IDs and their pinned deployed-runtime codehashes;
5. one exact target record for the connected chain and an observation block at or after its deployment;
6. byte-for-byte runtime codehash matches for the governance contract, version registry, raw verifier,
   `ZkIdentityPredicateProver` adapter and permanent `PredicateVerifier` host;
7. the version registry and permanent host are both owned by the approved governance contract;
8. the circuit ID is not already registered; and
9. the permanent host's proof path is still unset.

The result contains ordered `registerCircuit` and `authorizeIssuer` calldata. It separately contains
`setPredicateProver` calldata marked `executeOnlyAfterStatusAdmission`. The latter must not execute until an
authenticated status root/policy, holder end-to-end proof, replay/freshness failures and current operator evidence
have passed their own gate. A production profile cannot turn a status candidate into an accepted root.

## Live preflight

Run against a read-only RPC endpoint:

```bash
V2_PROFILE_RPC_URL="https://..." \
  pnpm --filter @ubi2/sdk admit:v2-profile -- path/to/production-profile.json
```

The command pins one latest block, then reads chain ID, deployed code, both owners, the current host prover and the
circuit registry slot at that exact block. On success it prints the observation block, admission record and calldata
as JSON. On failure it prints one bounded, URL-redacted reason and exits nonzero. The RPC URL stays in the
environment and is never printed. The command cannot sign or submit a call.

Governance proposal tooling must accept only this output, display the manifest hash, and preserve the two-phase
order. Direct registry or host activation outside this reviewed path is an unauthorized release process.

## Security and privacy

- The gate handles only public artifacts, addresses, codehashes and reports. It accepts no passport claim, holder
  secret, credential ciphertext, raw Self nullifier, issuer private key, mnemonic or keystore.
- A manifest is an integrity envelope, not an authorization signature. Authorization remains the timelocked
  governance execution after human review of the content-addressed evidence.
- Matching runtime code does not prove circuit soundness. Independent audits, setup verification and source-to-
  bytecode reproduction remain mandatory evidence.
- Compromising a mutable evidence host does not change the reviewed digest, but availability/archival remains a
  release responsibility.
- The denylist is defense in depth. Reviewers must still confirm that the production circuit ID and runtime are
  derived from the audited sources rather than renamed research artifacts.

## Rollout and migration

One manifest represents one circuit profile and may list multiple independently measured target chains. A phased
rollout can approve an additive manifest with fewer targets, then publish a new manifest hash when another chain's
evidence is ready. Existing circuit IDs are never reinterpreted; upgrades use a new ID and additive registration.

The five Phase 2 testnet deployments stay v1-only with `prover == address(0)`. V2 requires a corrected registry,
adapter and host deployment whose ownership and codehashes pass this gate. L2 activation precedes Ethereum unless
the approved target evidence explicitly supports simultaneous release.

## Ratified inputs and remaining work

The exact cryptographic fields and content-addressed pre-ceremony artifacts are listed in
[`fixtures/v2-production-crypto/admission-inputs-v1.json`](../../fixtures/v2-production-crypto/admission-inputs-v1.json).
Release must copy only the selected values and independently verified artifact digests into one manifest per
circuit. Placeholder URLs, zero digests or the deterministic reference signature/proof are forbidden.

- circuit/verifier: implement the four remaining relations, complete independent audits and publish canonical
  constraint systems plus MPC-derived proving/verifying artifacts for every admitted circuit;
- holder/prover: finish isolated local proving, vault/recovery and representative device evidence;
- operations: publish live status-root admission evidence for the corrected stack;
- QA/reliability/security: produce the required independent reports and close all Critical/High findings;
- release: add status admission and governance proposal/broadcast tooling after those inputs exist.
