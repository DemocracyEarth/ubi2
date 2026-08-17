# ADR-0012 — Freeze the V2 cross-lane wire contract before production cryptography

- **Status:** accepted for cross-lane integration; production cryptographic suite remains unratified
- **Date:** 2026-08-16
- **Decider:** V2 release and integration lead
- **Consumers:** holder/prover, circuit/verifier, testnet operations, SDK, EVM contracts and release gates
- **Related:** [ADR-0009](0009-predicate-v2-and-final-onchain-surface.md),
  [ADR-0010](0010-direct-v2-portable-zk-credential.md),
  [ADR-0011](0011-dynamic-status-freshness.md), and
  [EVM ZK Identity v2](../10-evm-zk-identity-v2.md)
- **Canonical vector:**
  [`fixtures/v2-identity/interface-v1.json`](../../../fixtures/v2-identity/interface-v1.json)

## Context

Three lanes now work in parallel:

1. testnet operations consumes issuance events and publishes independently reconciled packed-status artifacts;
2. holder/prover creates the private credential, protects it in the vault and generates local proofs; and
3. circuit/verifier authenticates the credential, status witness, policy, bindings and nullifier before emitting
   the EVM public signals.

The repository already pins most EVM-visible interfaces, but its benchmark Poseidon parameters, Baby-Jubjub
signature construction, deterministic Groth16 setup and research circuit identifiers are explicitly unaudited.
Treating those research choices as production protocol would make the three lanes appear compatible while silently
promoting toxic-waste fixtures into a release trust root. Waiting to freeze every interface until the final circuit
is audited creates the opposite risk: each lane can choose a different field order, scope or status convention.

## Alternatives considered

### A. Freeze nothing until the production circuit is complete

This minimizes early commitments, but it blocks meaningful end-to-end work and makes interface drift likely. The
holder and circuit lanes cannot independently test compatibility, and operator evidence cannot state which status
semantics it exercised.

### B. Freeze the complete research circuit as production V1

This offers immediate byte-level compatibility, but it promotes public toxic waste, unaudited Poseidon/signature
parameters and local-only gas measurements. It is rejected for security and ceremony reasons.

### C. Freeze the wire contract and testnet status profile, keep production cryptography versioned and gated

This lets every lane share one deterministic external contract while preserving an explicit cryptographic
ratification boundary. It is the selected option.

## Decision

### Frozen V1 wire contract

The following are compatible only when they match the canonical vector byte-for-byte. A change requires a new
version/profile and additive migration; it must not reinterpret version `1`.

- The private credential ABI field order and EVM types from spec 10. Its Keccak fingerprint is a drift detector,
  not the circuit commitment and never a public presentation identifier.
- The chain-and-registry issuance domain. The duplicate key remains one-way, registry-scoped and absent from
  events; a raw Self/passport nullifier is forbidden in calldata, events, storage, responses and logs.
- The nullifier scope and ordered six-field circuit preimage. Subject, challenge and epoch remain excluded so a
  wallet change, challenge refresh or time change cannot create a second one-per-scope slot.
- The exact 18-field public-signal layout, including lossless high/low `bytes32` limbs, a nonzero scoped nullifier,
  a canonical `uint160` subject, Boolean result, `uint32` credential epoch and ADR-0011 snapshot timestamp.
- The permanent `IPredicateProver` return tuple, the additive replay identifier, the host-authenticated consumer
  envelope and the three-word application context.
- Issuance/status semantics for the canonical V2 testnet integration profile: monotonic non-reused `uint32`
  status slots, 256 slots per chunk, a depth-24 packed tree, `0 = allocated and active`, and
  `1 = unallocated or revoked`. Slot zero remains a sentinel. Operators and circuits must identify this as a
  testnet integration profile until the hash suite below is ratified.
- Dynamic-status policy semantics: the policy commits to provider, list version, exact root and maximum age;
  signal 17 equals the exact governed publication Unix time and freshness is inclusive at the boundary.

The checked-in vector is synthetic. It contains no real passport data or stable production identifier. TypeScript,
Rust and Solidity tests all consume that same file and include positive decoding plus fail-closed mutation cases.

### Not frozen or production-authorized

The following remain explicit circuit/verifier deliverables and mainnet blockers:

- the circuit-native credential commitment function, domain constants and hash parameters;
- issuer signature scheme, point/scalar encodings, subgroup checks and nonce derivation;
- the production packed-tree hash parameters and root/profile identifier;
- production circuit identifiers and the exact policy circuit set;
- proof-system selection, compiler/toolchain, Phase 2 ceremony, proving/verifying keys and verifier bytecode;
- target-device proving budgets and target-chain raw/full gas budgets.

Research fixtures may exercise the frozen wire contract, but their circuit IDs, roots, proofs, keys and verifiers
must be labeled non-deployable. No deployment manifest or registry proposal may reference them.

The holder/prover lane must not persist or issue a credential until it can produce the selected circuit-native
commitment. The circuit/verifier lane must publish the selected commitment/signature/status parameter manifest and
vectors. The release lane then adds those values as a new versioned cryptographic profile without changing the V1
wire layout unless an audited constraint requires a new layout version.

## Compatibility and migration

- The five existing Phase 2 `PredicateVerifier` testnet deployments remain v1 issuer-only. Their prover stays
  unset. V2 uses a new corrected host/registry/adapter/verifier stack.
- A circuit upgrade is additive: a new circuit ID and verifier codehash are registered; an existing circuit ID is
  never reinterpreted. Root windows may overlap only through the explicit registry lifecycle.
- If the selected production suite cannot implement this wire contract soundly, the change uses public-signal
  layout version `2` and a new adapter. It does not weaken canonicality or silently reorder version `1`.
- A credential-commitment algorithm change after issuance requires an explicit credential migration/reissuance
  plan because the issuance registry globally consumes the commitment. It is not an adapter-only change.

## Consequences

### Privacy

No new public field is introduced. The stable private-credential fingerprint remains diagnostic only; the
credential commitment is absent from presentation signals, and the scoped nullifier remains consumer/context/
policy bound. Packed-status distribution is public and unkeyed so a holder need not identify its private slot to a
witness endpoint, but update metadata remains part of the privacy review.

### Security

Research cryptography cannot pass as a production profile. Canonical field checks, lossless limbs, exact root/time
binding and wallet-independent replay remain fail closed. The cost is that issuance-to-proof integration stays
blocked until the circuit/verifier lane ratifies and publishes the production cryptographic profile.

### Gas and implementation

This decision changes no deployed bytecode and adds no runtime gas. It preserves the measured 18-signal adapter
shape. A later production suite must measure its own raw verifier and full stateful path on every target chain;
local Cancun research values are not release budgets.

## Release gate

CI must run the shared vector in TypeScript, Rust and Solidity. A worker PR that changes a frozen field, index,
scope, status convention or verifier ABI must update this ADR with a versioned migration, add positive and negative
vectors, and state which lanes must rebase. Updating only one language is a release-blocking failure.

Production activation is additionally governed by the
[`org.proofofhumanity.zk-production-profile/1`](../v2-production-profile-admission.md) admission manifest. Freezing
the wire layout does not satisfy that gate: audited artifact/setup provenance, live runtime codehashes, independent
reports, mobile measurements and target-chain evidence remain mandatory.
