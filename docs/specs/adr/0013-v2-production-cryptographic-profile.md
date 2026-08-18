# ADR-0013 — Ratify the V2 production cryptographic profile for implementation

- **Status:** accepted for implementation; not production-approved or activated
- **Date:** 2026-08-18
- **Deciders:** product owner, circuit/verifier owner and V2 integration lead
- **Profile:** `org.proofofhumanity.v2-crypto.groth16-bn254-poseidon/1`
- **Parameters and vectors:** [`fixtures/v2-production-crypto/`](../../../fixtures/v2-production-crypto/)
- **Admission gate:** [`v2-production-profile-admission.md`](../v2-production-profile-admission.md)
- **Parent:** [ADR-0012](0012-v2-cross-lane-interface-freeze.md)

## Decision boundary

This ADR ratifies one exact suite so circuit, holder, SDK and operator implementations can stop using an
ambiguous “research hash” placeholder. Ratification means the identifiers, encodings, domains and algorithms in
the parameter manifest are implementation-stable. A change requires a new profile, new vectors and additive
credential/circuit migration.

It does **not** approve a circuit or verifier for production. No deterministic toxic-waste key is promoted. Every
circuit still needs its own audited constraint artifact, circuit-specific multiparty setup, proving/verifying key,
verifier bytecode, device evidence, live deployment evidence and `production-approved` admission manifest. The
checked-in deterministic vector uses a public synthetic issuer secret and ISO user-assigned country codes
`XAA`/`XAB`; none of it may be reused for issuance.

## Selected profile

### Credential commitment and normalization

The V1 private-credential field order and normalization in
[`v2-holder-credential-commitment.md`](../v2-holder-credential-commitment.md) are ratified unchanged. The
commitment is one canonical BN254 scalar:

```text
C = Poseidon(domain = 1, ordered privateCredentialV1 fields[0..15])
```

Poseidon is over BN254 Fr, width 3, rate 2, capacity 1, exponent 5, 8 full rounds and 57 partial rounds. Constants
are the exact output of arkworks 0.5 with `skip_matrices = 0`; every ARK and MDS element is published in
`parameters-v1.json`. Absorption always starts with one domain field element. An implementation must not substitute
another Poseidon generator merely because its round counts match.

The commitment binds schema/version, issuer key identifier, nonzero status slot, holder secret, independent
blinding, normalized passport facts and issuance epoch. It is public once at issuance but absent from the frozen
presentation signals. A losing slot/epoch allocation is resolved by discarding the unsigned candidate, committing
to the newly observed slot/epoch and repeating passport binding. Rewriting a signed commitment is forbidden. This
selects the safest no-ABI-change race behavior; reservation and two-stage commitment remain possible future
profiles.

### Issuer authentication

The issuer signs `C` with the profile's Schnorr relation on the prime-order Baby-Jubjub subgroup:

```text
A = sk * G
e = Poseidon(domain = 4, [R.x, R.y, A.x, A.y, C]) mod subgroupOrder
s = r - e * sk mod subgroupOrder
verify: s * G + e * A = R
issuerKeyId = bytes32(Poseidon(domain = 5, [A.x, A.y]))
```

Secret scalars are canonical nonzero big-endian 32-byte integers below the subgroup order. Responses use the same
canonical scalar encoding but may be zero. Points are two canonical big-endian BN254-Fr coordinates and must be on
curve, nonzero and prime-subgroup checked. Equality to the sum of two subgroup points also constrains `R` to the
prime subgroup.

Nonce derivation is SHA-512 over the exact domain, canonical secret scalar, credential commitment, mandatory fresh
32-byte issuer CSPRNG auxiliary randomness and a big-endian counter. The digest is reduced modulo the subgroup
order; a zero result advances the counter. The auxiliary randomness is private ephemeral issuer state and must
never enter the issuance transcript, logs or credential. This exact custom envelope requires independent
cryptography review before admission; ratification prevents implementations from inventing incompatible variants.

Baby Jubjub is the EIP-2494 curve over the BN254 scalar field. The profile publishes arkworks' reduced Edwards
coefficients and generator coordinates rather than relying on a curve nickname. See
[EIP-2494](https://eips.ethereum.org/EIPS/eip-2494).

### Status and nullifier hashes

The production status profile is a depth-24 packed Poseidon tree. A nonzero `uint32 statusId` uses its low eight
bits as the bit index and the remaining 24 bits as the path. Each 256-bit chunk is two little-endian `u128` field
limbs: `0 = allocated and active`; `1 = unallocated or revoked`. Leaves use domain 8 and nodes use domain 3.

The scoped nullifier keeps ADR-0012's six-field preimage and domain 2. Credential commitment, issuer signature,
status leaf/node and nullifier domains are distinct. The governed root and publication time remain public; the
holder's slot, bit, chunk and path remain private.

### Proof system, circuit set and toolchain

The proof system is circuit-specific Groth16 over BN254. It fits the existing EVM pairing interface and measured
gas shape through [EIP-196](https://eips.ethereum.org/EIPS/eip-196) and
[EIP-197](https://eips.ethereum.org/EIPS/eip-197). Each circuit has a separate Phase 2 MPC with at least three
verified contributions, a final beacon and independent reproduction. Deterministic setup is permitted only for
tests and can never populate a production admission manifest.

The additive V1 circuit set is:

1. sanctions clear under a current governed packed-status root;
2. minimum age at a policy-bound date;
3. membership in a policy-bound canonical nationality set;
4. credential unexpired at a policy-bound date; and
5. minimum passport-authentication assurance.

Circuit IDs are Keccak-256 of the exact preimages in `circuit-set-v1.json`. Only the generic sanctions/status
relation has an implementation candidate today; its deterministic research verifier is not a production artifact.
The other four relation and artifact sets remain implementation work. A combined policy circuit may be added under
a new circuit ID, but existing IDs cannot be reinterpreted.

The compiler lock is Rust 1.96.0, arkworks R1CS/Groth16 0.5.x at the exact Cargo lock, wasm-bindgen 0.2.125, and
Solidity 0.8.28 with optimizer 200/Cancun. The arkworks Groth16 repository describes itself as academic software
that has not received a production review; this ADR therefore requires independent source-to-constraint,
cryptography and verifier review rather than treating a version pin as an audit. See the
[arkworks Groth16 repository](https://github.com/arkworks-rs/groth16).

## Frozen ABI and privacy

No Solidity ABI, status publication format or presentation signal changes. Every circuit emits the exact 18
signals in `public-signals-v1.json`. Circuit/issuer IDs, accepted status root and time, policy and presentation
bindings, scoped nullifier, subject, Boolean result and credential epoch are public. Passport attributes, holder
secret, blinding, commitment, signature, status slot/path and predicate witnesses remain private during
presentation. The NFT remains only an ownership, issuer-authorization, validity and revocation anchor; it contains
no passport attribute, ciphertext or linkable credential identifier.

## Reproducible package

`fixtures/v2-production-crypto/` contains:

- the full Poseidon, curve, signature, status, proof-system and toolchain parameter manifest;
- one deterministic end-to-end component vector with canonical credential fields, commitment, issuer signature,
  packed-status root, nullifier preimage and 18 public signals;
- the circuit-set, compiler and public-signal manifests;
- a SHA-256 artifact index; and
- the exact selected and pending inputs for `org.proofofhumanity.zk-production-profile/1`.

CI regenerates the parameter and reference-vector JSON byte-for-byte and verifies every indexed digest. The vector
is a protocol interoperability oracle, not a production proof or key.

## Admission blockers after ratification

There is deliberately no checked-in production profile manifest yet. The exact remaining inputs are published in
`admission-inputs-v1.json`:

- implement and audit every admitted circuit relation;
- publish canonical constraint systems and ceremony-derived proving/verifying artifacts;
- independently verify the ceremony and source-to-artifact reproduction;
- close all Critical and High circuit, cryptography, Solidity, privacy, QA, reliability and security findings;
- collect representative mid-range-mobile proving evidence; and
- deploy the governed verifier stack, measure target-chain gas and publish exact runtime codehashes.

Only then may release create a `production-approved` per-circuit manifest and invoke the existing live admission
gate. This separation is intentional: the holder Worker/WASM engine may now target the ratified profile and
content-addressed artifacts, but it must reject missing/unapproved proving artifacts and must not use the public
deterministic vector key.
