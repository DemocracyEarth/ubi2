# ZK Identity v2 cryptographic benchmark

This isolated research harness measures the first Stage 1 credential-authentication candidates for
[ZK Identity v2](../../docs/specs/10-evm-zk-identity-v2.md). It is deliberately a separate Cargo workspace:
its circuit gadgets and prover dependencies do not enter the production `ubi2-zkpoh` verifier graph.

This is **not a production circuit, security audit, parameter ratification, or final cryptographic decision**.

## Relations measured

Every candidate performs the same common work:

- a domain-separated Poseidon commitment over all 13 logical fields in the pinned private-credential ABI,
  encoded as 16 field elements because each of the three `bytes32` values is split into lossless 128-bit limbs;
- a domain-separated Poseidon scoped nullifier over the pinned six-field preimage;
- structural reuse of the credential's authenticated `holderSecret` as the nullifier preimage's
  `holderSecret` (there is no second independently allocated secret); and
- equality of the computed nullifier with a public input.

The authentication delta is then:

| Candidate | Additional relation | Operational trade-off |
|---|---|---|
| Issuer signature | Baby-Jubjub Schnorr/EdDSA-style equation with a Poseidon challenge | Authenticates issuance without a membership witness; revocation/status still needs a separate mechanism. |
| Active registry | Depth-32 Poseidon Merkle membership of the credential commitment | Combines issuance authorization and active status, but requires root governance and holder witness updates. |
| Signature + registry | Both relations | Defense in depth and explicit separation of authenticity/status at the highest circuit cost. |
| Signature + packed status | Issuer signature plus a non-revoked bit in a 256-status chunk under a depth-24 Poseidon root | Separates authenticity from status, avoids hashed-leaf collisions for a canonical 32-bit assigned slot, and amortizes public updates across a chunk. Uniqueness remains a separate registry concern. |

The signature model keeps issuer public-key coordinates private, enforces prime-subgroup membership, derives a
domain-separated Poseidon key digest, and binds that digest losslessly to the two public 128-bit `issuerKeyId`
limbs already pinned at signal indices 3–4. The same limbs are structurally reused inside the private credential
commitment. Wrong keys, identifiers, signatures, and non-128-bit limbs fail closed. The exact signature scheme,
encoding, nonce derivation, domain constants, and Poseidon parameters still require cryptographic review. The
bytes32 reconstruction also rejects values at or above the BN254 field modulus before equality, preventing modular
aliases.

The packed-status candidate treats the signed `statusId` as one canonical issuer-assigned `uint32` slot. The low
eight bits select one of 256 revocation bits and the next 24 bits select that chunk's Merkle path, covering up to
2^32 slots. Each chunk is encoded losslessly as two little-endian 128-bit field limbs; zero means active and one
means revoked. The circuit authenticates the complete credential with the issuer signature, proves the selected
bit is zero, binds the depth-24 path to the slot, and binds the public root losslessly. Tests reject a set target
bit, changed path/root, non-canonical slot or chunk limbs, and root modular aliases. This assigned-slot convention,
status authority, checkpoint governance and wire encoding are research inputs, not a migration of the operational
depth-32 registry or a ratified ABI.

The active-registry model binds the credential commitment and private two-limb `statusId` into the active leaf.
It derives the depth-32 path from `Poseidon(statusId)` inside the circuit and binds the root losslessly to the two
public limbs already pinned at signal indices 5–6. Its public `issuerKeyId` limbs are canonical and structurally
reused inside the credential commitment; the registry authorizes the resulting issuer/credential pair without
exposing issuer key coordinates. Tests distinguish revocation, a stale witness after an unrelated leaf update, and
a valid refreshed witness.
The benchmark's public-input counts cover only the relation delta; the product adapter retains the separately
pinned 18-field public-signal layout. Attribute range/country/date predicates, presentation-binding checks,
the other public bytes32-to-limb bindings and field-specific canonicality constraints are outside this spike;
the counts below are not an estimate for the complete presentation circuit.

## Operational status-registry prototype

[`status_registry.rs`](src/status_registry.rs) now exercises the complete holder witness lifecycle against the
same Poseidon domains and depth-32 relation as the benchmark circuit:

- activation reserves the private status-derived leaf index and returns the initial holder witness;
- revocation replaces the active leaf with zero and future witness requests fail closed;
- every mutation emits a versioned, canonical JSON delta containing only the changed index, old/new leaf and
  sibling path — never the raw `statusId` or credential commitment — so clients can recompute both declared roots;
- holders download the same unkeyed delta feed, update their witness locally, and do not identify their credential
  to a witness endpoint;
- missing, reordered, malformed, non-canonical or tampered deltas fail without mutating the saved witness;
- a refreshed witness is accepted only if its final epoch/root matches an independently trusted checkpoint; and
- direct circuit tests prove that initial and locally refreshed witnesses satisfy the exact active-registry
  relation, including a batch with many unrelated activations and revocations.

This remains a transport-neutral, in-memory research prototype. An unkeyed feed avoids a lookup privacy leak, but
the public changed index and leaf can still be correlating metadata if exposed without a broader anonymity model.
Production work must define authorized issuance/revocation, durable storage, authenticated checkpoint governance,
delta retention/snapshots, availability/fork handling, privacy analysis, and browser/WASM integration before this
becomes a network service or SDK feature.

Depth 32 is retained only to match the measured circuit. A 32-bit hashed index reaches approximately 50% collision
probability near 77,000 registrations, so the prototype rejects collisions instead of overwriting a credential.
That is fail-closed behavior, not production scale: the final ADR must measure a deeper tree or another accumulator.

## Registry-depth sensitivity

The relation is now parameterized and CI pins 32/64/96/128-depth profiles. These measurements isolate depth only;
the active leaf, status-derived index, canonical public root and five public inputs are otherwise identical. The
50% column is the approximate number of uniformly hashed registrations at which at least one index collision becomes
more likely than not; collision rejection/resampling does not make a shallow index cryptographically stronger.

Measured 2026-08-13 using the same release toolchain and desktop class as the baseline. Timings are one warm-binary
sample and are not portable budgets.

| Depth | Constraints | Witness vars | 50% collision registrations | Setup | Prove | Verify | Proof | VK |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 32 | 21,723 | 21,301 | 77,163 | 707 ms | 692 ms | 0.74 ms | 128 B | 424 B |
| 64 | 37,147 | 36,757 | 5.06 billion | 1,204 ms | 1,201 ms | 0.74 ms | 128 B | 424 B |
| 96 | 52,571 | 52,213 | 331 trillion | 1,545 ms | 1,562 ms | 0.74 ms | 128 B | 424 B |
| 128 | 67,995 | 67,669 | 21.7 quintillion | 2,199 ms | 2,252 ms | 0.74 ms | 128 B | 424 B |

Each extra level costs approximately 482 constraints; every additional 32 levels add exactly 15,424 constraints in
this relation. Depth 96 is the current scale/cost candidate to beat: it removes the immediate global-population
collision ceiling at 52,571 constraints, while depth 128 adds another 15,424 constraints for a larger targeted-index
security margin. This is not a selection. Browser/mobile time and peak memory, public-delta bandwidth, adversarial
index allocation, EVM gas and alternate accumulators still decide the ADR.

## Browser/WASM feasibility

The `browser/` harness is a real Web Worker/WASM proving path for depths 96 and 128. Setup runs in a disposable
worker only to create a deterministic fixture proving key. The holder path starts a fresh worker, validates and
deserializes that compressed key, generates a Groth16 proof and verifies it before reporting success. Fresh workers
prevent the second depth from reusing the first run's already-grown allocator.

Measured 2026-08-13 in Chromium 150 on the same aarch64 macOS workstation as the desktop baseline. Three consecutive
runs per profile verified; the table records the middle machine-readable capture (holder-path totals spanned
15.12–15.34 s at depth 96 and 20.87–21.15 s at depth 128). These are feasibility observations, not portable budgets
or mobile results. “Memory” is retained WASM linear memory after the call: because WebAssembly memory grows in pages
and does not shrink, it is a useful high-water signal for this worker, but it is not total browser-process or device
memory.

| Depth | Setup | Proving key | Setup memory | Key validate/load | Prove | Verify | Holder-path total | Prover memory |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 96 | 4.42 s | 10,452,496 B | 177,143,808 B | 11.08 s | 4.23 s | 2 ms | 15.33 s | 214,368,256 B |
| 128 | 6.24 s | 15,022,608 B | 232,980,480 B | 14.94 s | 6.07 s | 2 ms | 21.04 s | 291,897,344 B |

Both proofs verified and remained 128 bytes with a 424-byte verifier key. Depth 128 used 43.7% more proving-key
bandwidth, 36.2% more retained prover memory and 37.2% more holder-path time than depth 96 in this run. Both are under
the roadmap's 60-second modern-device ceiling on this desktop-class browser, but depth 96's roughly 204 MiB retained
memory is not evidence that mid-range mobile devices are safe. Depth 96 therefore remains the candidate to beat, not
a selected production parameter.

### Registry transport lower bounds

The deterministic transport report projects only fixed-width binary content: epochs, roots, old/new leaves, the
delta's depth-sized index and Merkle siblings. The operational prototype remains depth 32 with a `u32` index; deeper
rows do not migrate that wire schema. The report deliberately excludes schema/framing, authenticated checkpoints,
signatures, compression and request overhead. Its delta values are uncompressed lower bounds for this one-path-per-
mutation model; pseudorandom field elements should not be assumed compressible.

| Depth | Holder witness floor | One delta floor | 1,000 updates | 100,000 updates per holder |
|---:|---:|---:|---:|---:|
| 32 | 1,092 B | 1,164 B | 1.164 MB | 116.4 MB |
| 64 | 2,116 B | 2,192 B | 2.192 MB | 219.2 MB |
| 96 | 3,140 B | 3,220 B | 3.220 MB | 322.0 MB |
| 128 | 4,164 B | 4,248 B | 4.248 MB | 424.8 MB |

This rules out treating the prototype's full unkeyed, one-path-per-mutation feed as the production distribution
strategy at global update volumes. The privacy goal remains—holders must not query by private `statusId`—but the ADR
must measure batched/multiproof deltas plus authenticated snapshots, or select a different accumulator.

### Status-distribution bakeoff

The follow-up deterministic model compares a depth-96 one-credential-per-leaf sparse tree against the depth-24
packed-status candidate. Both use a public, unkeyed update stream. A batch includes two epochs/roots, every changed
index and old/new leaf material, plus the exact number of sibling nodes in a Merkle multiproof. The packed strategy
also computes a full 256-bit-per-chunk snapshot and selects the smaller delivery; a pinned dense-change fixture
exercises the snapshot branch. These are uncompressed fixed-width binary lower bounds. They exclude framing,
authentication/signatures, checkpoint distribution, compression, fork recovery and request overhead.
The snapshot rows assume dense zero-based slot allocation, so snapshot size follows the allocated high-water mark;
sparse or adversarial slot assignment would invalidate that projection and must be rejected by the final design.

| Workload | Depth-96 sparse batch | Packed changed chunks | Packed batch/snapshot | Reduction vs sparse |
|---|---:|---:|---:|---:|
| 100M credentials / 1,000 changes | 2,800,008 B | 1,000 | 312,640 B batch | 88.83% |
| 100M credentials / 100,000 changes | 258,800,968 B | 88,279 | 10,510,477 B batch | 95.93% |
| 1B credentials / 100,000 changes | 258,802,024 B | 98,756 | 20,823,540 B batch | 91.95% |

The packed holder-witness floor is 836 B (epoch, root, 32-byte chunk and 24 siblings), versus 3,140 B for the
depth-96 sparse model. Full packed snapshots are 12,500,036 B for 100M slots and 125,000,036 B for 1B slots.
Batching alone only reduces the modeled sparse stream by 13.04%–19.62%; most leaves do not share enough of a
96-level pseudorandom path. Packing changes that scaling because many status changes share a chunk and every proof
uses a 24-level path. The result makes signature + packed status the candidate to beat for authenticity plus
revocation, not a selection: issuer slot allocation, duplicate prevention, authorization, checkpoint availability,
privacy metadata, mobile proving and EVM verification still need production design and measurement.

## Reproduce

Requires the Rust toolchain pinned at the repository root.

```bash
cargo fmt --manifest-path tools/v2-crypto-bench/Cargo.toml -- --check
cargo test --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked
cargo test --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked \
  all_candidates_generate_verified_groth16_proofs -- --ignored
cargo run --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked
cargo run --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked -- \
  --registry-depths --constraints-only
cargo run --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked -- \
  --transport-estimates
cargo run --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked -- \
  --status-distribution
```

Use `-- --constraints-only` on the baseline or registry-depth suite for deterministic relation metadata without
Groth16 setup or proof timing. Transport estimates are deterministic by construction. CI pins the exact constraint
counts and performs a proof round trip for every candidate.

To reproduce the actual browser flow, generate the ignored web bindings and serve the static runner from the
repository root:

```bash
wasm-pack build tools/v2-crypto-bench --target web --out-dir browser/pkg --release -- \
  --features browser --locked
python3 -m http.server 4173 --bind 127.0.0.1 --directory tools/v2-crypto-bench/browser
```

Open `http://127.0.0.1:4173/`, run both profiles and download the machine-readable report if needed. The generated
`browser/pkg/` directory is git-ignored; CI independently compiles the bridge for `wasm32-unknown-unknown`. The runner
pins each deterministic fixture key's exact byte length and SHA-256 digest, checks the digest again after worker
transfer, and then uses validated arkworks deserialization. Production must independently pin the ceremony artifact
digest and deployed verifier key; these fixture fingerprints are not deployable trust anchors.

## Preliminary desktop baseline

Measured 2026-08-12 using `rustc 1.96.0`, release mode, aarch64 macOS 26.5.2. Timings are a single warm-binary
sample and are included only to validate the harness and establish an order of magnitude; they are not a product
budget and must not be compared across machines as if deterministic.

| Candidate | Constraints | Witness vars | Public inputs | Setup | Prove | Verify | Proof | VK |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Issuer signature | 13,528 | 12,916 | 3 | 1,003 ms | 809 ms | 1.42 ms | 128 B | 360 B |
| Active registry | 21,723 | 21,301 | 5 | 1,708 ms | 1,431 ms | 1.24 ms | 128 B | 424 B |
| Signature + registry | 31,843 | 30,793 | 5 | 3,177 ms | 2,372 ms | 1.82 ms | 128 B | 424 B |
| Signature + packed status | 27,157 | 26,253 | 5 | 897 ms | 835 ms | 0.94 ms | 128 B | 424 B |

The packed-status row was measured 2026-08-14 on the same workstation after the original rows and is not a timing
comparison with those earlier warm-binary samples. Its proof verified. At 27,157 constraints it is 4,686 constraints
(14.7%) smaller than signature + depth-32 per-credential registry while providing a separate revocation relation.

The deterministic result is that direct signature authentication is 8,195 constraints (37.7%) smaller than the
depth-32 registry relation in this harness. That makes the signature relation the current candidate to beat for
credential authenticity, not the selected production design: revocation still needs a measured status mechanism,
and a registry may remain valuable even if it is not the primary issuer-authentication primitive. A final ADR
still requires:

- a reviewed alternate SNARK-native hash and at least one universal-setup proof-system comparison;
- repeated browser/WASM and mid-range mobile time and peak-memory measurements;
- EVM verifier bytecode/gas measurements on the target L1/L2s;
- active-root governance, revocation latency, transport/retention and production witness-distribution hardening; and
- a circuit threat model, constraint audit, setup/ceremony plan, and independent review.
