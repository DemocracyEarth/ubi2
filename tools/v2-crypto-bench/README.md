# ZK Identity v2 cryptographic benchmark

This isolated research harness measures the first Stage 1 credential-authentication candidates for
[ZK Identity v2](../../docs/specs/10-evm-zk-identity-v2.md). It is deliberately a separate Cargo workspace:
its circuit gadgets and prover dependencies do not enter the production `ubi2-zkpoh` verifier graph.

This is **not a production circuit, security audit, parameter ratification, or final cryptographic decision**.

## Relations measured

Every candidate performs the same common work:

- a domain-separated Poseidon commitment over all 13 logical fields in the pinned private-credential ABI,
  encoded as 16 field elements because each of the three `bytes32` values is split into lossless 128-bit limbs;
- a domain-separated Poseidon scoped nullifier over the pinned six-field preimage; and
- structural reuse of the credential's authenticated `holderSecret` as the nullifier preimage's
  `holderSecret` (there is no second independently allocated secret); and
- equality of the computed nullifier with a public input.

The authentication delta is then:

| Candidate | Additional relation | Operational trade-off |
|---|---|---|
| Issuer signature | Baby-Jubjub Schnorr/EdDSA-style equation with a Poseidon challenge | Authenticates issuance without a membership witness; revocation/status still needs a separate mechanism. |
| Active registry | Depth-32 Poseidon Merkle membership of the credential commitment | Combines issuance authorization and active status, but requires root governance and holder witness updates. |
| Signature + registry | Both relations | Defense in depth and explicit separation of authenticity/status at the highest circuit cost. |

The signature model enforces prime-subgroup membership for the issuer key and signature commitment. Its exact
scheme, encoding, nonce derivation, domain constants, and Poseidon parameters still require cryptographic review.
This first relation exposes the issuer public-key coordinates directly so their circuit cost is visible; binding
those coordinates losslessly to the pinned 18-field `issuerKeyId` (or pinning a key per additive circuit version)
is an explicit compatibility item for the next slice and is not solved by this harness.
The benchmark's public-input counts cover only the relation delta; the product adapter retains the separately
pinned 18-field public-signal layout. Attribute range/country/date predicates, presentation-binding checks,
bytes32-to-limb binding, and field-specific canonicality constraints are also outside this authentication spike;
the counts below are not an estimate for the complete presentation circuit.

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
| Issuer signature | 11,995 | 11,696 | 3 | 528 ms | 527 ms | 0.89 ms | 128 B | 360 B |
| Active registry | 18,605 | 18,656 | 2 | 1,713 ms | 1,010 ms | 0.82 ms | 128 B | 328 B |
| Signature + registry | 27,452 | 27,184 | 4 | 1,319 ms | 1,444 ms | 0.90 ms | 128 B | 392 B |

The deterministic result is that direct signature authentication is 6,610 constraints (35.5%) smaller than the
depth-32 registry relation in this harness. That makes the signature relation the current candidate to beat for
credential authenticity, not the selected production design: revocation still needs a measured status mechanism,
and a registry may remain valuable even if it is not the primary issuer-authentication primitive. A final ADR
still requires:

- a reviewed alternate SNARK-native hash and at least one universal-setup proof-system comparison;
- repeated browser/WASM and mid-range mobile time and peak-memory measurements;
- EVM verifier bytecode/gas measurements on the target L1/L2s;
- active-root governance, revocation latency, and Merkle-witness update/failure testing; and
- a circuit threat model, constraint audit, setup/ceremony plan, and independent review.
