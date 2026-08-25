# V2 sanctions-clear audit and Phase 2 ceremony

- **Status:** source and canonical constraints frozen for independent audit; no audit approval or ceremony is
  claimed
- **Scope:** sanctions-clear circuit
- **Circuit ID:** `0xe04e432671953a25e6aadbb5e59cfa0ff347108e31aac4a5599cb08f5cce11d2`
- **Safety boundary:** artifact publication only; no transaction, deployment, registration or proof-path activation

## Frozen public review package

The freeze is byte-addressed by
[`sanctions-clear-source-freeze-v1.json`](../../fixtures/v2-production-crypto/sanctions-clear-source-freeze-v1.json).
It covers the circuit implementation, credential and profile code, dependency/toolchain locks, parameters, circuit
ID and 18-signal ABI. Any covered byte change invalidates the freeze and requires a new circuit ID, two new audits
and a new circuit-specific Phase 2 ceremony.

The complete canonical A/B/C matrices use the encoding specified in
[`sanctions-clear-constraint-system-v1.json`](../../fixtures/v2-production-crypto/sanctions-clear-constraint-system-v1.json).
The uncompressed constraint system is 20,467,203 bytes with SHA-256
`605b6511f4045f9447b018f7e7ab4d9c96a984afd94d2db9f2ac0bc4d636dbe8`. The checked-in deterministic gzip is
[`sanctions-clear-r1cs-v1.bin.gz`](../../fixtures/v2-production-crypto/sanctions-clear-r1cs-v1.bin.gz), SHA-256
`48983b02719eb0eacbb5cd934df909752d94a235eeec8bb67443c2c6c672876f`.

These files establish a review target. They are not an audit, trusted setup, proving key, verifying key or
production approval. The synthetic credential and public-toxic-waste research fixtures remain inadmissible.

Reproduce locally without creating setup material:

```bash
cd tools/v2-crypto-bench
cargo run --release --locked -- --production-sanctions-constraint-manifest
cargo run --release --locked -- --production-sanctions-source-freeze
cargo run --release --locked -- --write-production-sanctions-constraints /tmp/v2-sanctions-clear-r1cs-v1.bin
```

Hash the output without logging its contents. The canonical binary contains only public constraint matrices.

## Required independent participants

No ceremony may be scheduled until all roles below are named through public, non-secret identity records:

1. one circuit-audit organization that did not author the frozen circuit;
2. one separate cryptography-audit organization that did not author the profile or circuit;
3. one ceremony coordinator responsible for ordering public artifacts, not for supplying hidden entropy;
4. at least three real, uniquely identified Phase 2 contributors;
5. an independent contribution verifier that checks every link and the final beacon application;
6. an independent source-to-verifier reproducer from an organization distinct from both auditors and every
   contributor organization;
7. a public artifact custodian with an immutable HTTPS or IPFS interface and a separate availability mirror; and
8. an authoritative public timestamp provider that returns a durable, independently verifiable receipt.

Repository maintainers, automation and AI agents do not count as independent auditors, contributors or
reproducers. Test fixtures never count as real ceremony evidence.

## Audit gate before ceremony

Both audit reports and explicit approval receipts must bind the SHA-256 of the source-freeze manifest and the
uncompressed canonical constraint system. Each approval must be public, content-addressed, timestamped and state
zero open Critical and High findings. At minimum, reviewers must cover:

- every private credential field and all 18 public signals, including values intentionally authenticated by the
  adapter rather than the relation;
- Poseidon parameters/domains, bytes32 canonicality, Baby-Jubjub point and subgroup checks, Schnorr scalar/nonce
  handling, signed credential binding and scoped-nullifier ordering;
- packed-status bit selection, depth-24 path derivation, zero/unallocated/revoked semantics and public root
  reconstruction;
- boundary values, field-modulus aliases, malformed points, duplicate/cross-circuit witnesses, stale roots and
  every documented adversarial test; and
- the exact canonical-matrix encoder and the selected Phase 1/Phase 2 implementation. The repository currently
  supplies no independently approved MPC implementation, so selecting and reviewing that implementation is an
  explicit pre-ceremony blocker.

An audit that asks for a constraint change rejects this freeze. Do not patch the same circuit ID and continue.

## Ceremony sequence

1. Publish the merged freeze commit, a source archive, the source-freeze manifest, canonical constraints, compiler
   lock and both audit approvals. Verify every byte from a clean machine.
2. Record the reviewed Phase 1 transcript and the exact circuit-specific initial Phase 2 transcript. Record the
   selected ceremony tool source/version and its independent approval; do not use the benchmark's deterministic
   setup routine.
3. Announce contributor order and the public upload/verification interfaces. Each contributor generates fresh
   private entropy locally, uploads only the public contribution, erases local entropy, and publishes a receipt.
   Entropy, seeds, mnemonics, keys and command histories containing them must never enter chat, logs or Git.
4. After each of at least three unique contributors, independently verify the transcript and publish the input
   digest, output digest and verification receipt. A broken or unverifiable link aborts the ceremony.
5. Before its future value is knowable, publish the final-beacon source and commitment. After all contributions,
   reveal the public value, apply it once, independently verify it and publish the application report. A value
   selected or knowable before the commitment is not an acceptable beacon.
6. Publish the complete Phase 1 and Phase 2 transcripts, every contribution/verification receipt, final beacon,
   proving key, verifying key, generated verifier source and runtime bytes. Every artifact receives an exact byte
   length and SHA-256 and must be retrievable from the immutable public interface and mirror.
7. On a clean independent environment, reproduce the canonical constraints, verifying key, verifier source and
   runtime from the frozen source and final transcript. Publish a signed report that compares hashes, not names.
8. Build `org.proofofhumanity.v2-sanctions-clear-ceremony/1` and validate it with
   `parseV2SanctionsCeremonyRecord`. Externally timestamp the final artifact index and record a receipt whose
   subject SHA-256 is exactly the artifact-index digest.

Completion of these steps only yields inactive public artifacts. It does not authorize a transaction, deployment,
registry entry, governance proposal or `setPredicateProver` call.

## Public endpoint checklist

The coordinator must provide credential-free immutable URLs for:

- frozen source archive, source-freeze manifest, canonical constraints, parameters, compiler lock and signal ABI;
- circuit and cryptography audit reports, auditor identity records and explicit approval receipts;
- ceremony-tool source/review, Phase 1 transcript, initial Phase 2 transcript, all contribution receipts, all
  contribution verification receipts, beacon commitment/source/reveal/application and final transcript;
- proving key, verifying key, verifier source, verifier runtime and a canonical artifact index;
- independent reproducer identity, source-to-verifier report and approval receipt; and
- timestamp-authority identity plus final timestamp receipt.

Every URL path must contain the artifact's lowercase SHA-256 as a complete path segment. URLs containing
credentials, query strings or fragments are rejected. RPC endpoints, passwords, private keys, entropy and
environment files are never inputs to this workflow.

## Current exact blockers

- no independent circuit auditor or public approval receipt is designated;
- no separate independent cryptography auditor or public approval receipt is designated;
- no independently reviewed arkworks-compatible circuit-specific MPC implementation is selected;
- no reviewed Phase 1 transcript is designated;
- no ceremony coordinator, three contributors or contribution verifier is designated;
- no immutable artifact host, independent mirror or authoritative timestamp interface is designated;
- no final-beacon source and precommitment procedure is designated; and
- no independent source-to-verifier reproducer is designated.

Until every item is resolved with observed public evidence, `ceremonyComplete`, `productionApproved` and
`deploymentAuthorized` remain false.
