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

The signature model keeps issuer public-key coordinates private, enforces prime-subgroup membership, derives a
domain-separated Poseidon key digest, and binds that digest losslessly to the two public 128-bit `issuerKeyId`
limbs already pinned at signal indices 3–4. The same limbs are structurally reused inside the private credential
commitment. Wrong keys, identifiers, signatures, and non-128-bit limbs fail closed. The exact signature scheme,
encoding, nonce derivation, domain constants, and Poseidon parameters still require cryptographic review. The
bytes32 reconstruction also rejects values at or above the BN254 field modulus before equality, preventing modular
aliases.

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

## Reproduce

Requires the Rust toolchain pinned at the repository root.

```bash
cargo fmt --manifest-path tools/v2-crypto-bench/Cargo.toml -- --check
cargo test --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked
cargo test --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked \
  all_candidates_generate_verified_groth16_proofs -- --ignored
cargo run --manifest-path tools/v2-crypto-bench/Cargo.toml --release --locked
```

Use `-- --constraints-only` on the final command for deterministic relation metadata without Groth16 setup or
proof timing. CI pins the exact constraint counts and performs a proof round trip for every candidate.

## Preliminary desktop baseline

Measured 2026-08-12 using `rustc 1.96.0`, release mode, aarch64 macOS 26.5.2. Timings are a single warm-binary
sample and are included only to validate the harness and establish an order of magnitude; they are not a product
budget and must not be compared across machines as if deterministic.

| Candidate | Constraints | Witness vars | Public inputs | Setup | Prove | Verify | Proof | VK |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Issuer signature | 13,528 | 12,916 | 3 | 1,003 ms | 809 ms | 1.42 ms | 128 B | 360 B |
| Active registry | 21,723 | 21,301 | 5 | 1,708 ms | 1,431 ms | 1.24 ms | 128 B | 424 B |
| Signature + registry | 31,843 | 30,793 | 5 | 3,177 ms | 2,372 ms | 1.82 ms | 128 B | 424 B |

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
