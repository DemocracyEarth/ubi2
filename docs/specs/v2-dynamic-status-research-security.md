# V2 dynamic-status research circuit: security boundary and production gates

Status: **research evidence only**. The deterministic Groth16 setup seed and toxic waste are public. The generated
verifier, proof and verifying key must never be deployed, registered by a live `PredicateVerifier`, or treated as a
trusted setup.

## What the measured relation enforces

The `dynamic-status-packed-research-1` relation has 28,499 constraints, 27,561 witness variables and exactly 18
public inputs in the v1 product layout. It enforces:

- a Baby-Jubjub issuer signature over the complete 16-field circuit credential encoding;
- lossless binding of the signed issuer key identifier and credential epoch to public signals 3–4 and 16;
- a canonical signed `uint32` status slot whose selected revocation bit is zero under the depth-24 packed Poseidon
  root exposed at signals 5–6;
- the fixed research circuit identifier, canonical nonzero two-limb identifiers, a nonzero `uint160` subject,
  `result == true`, a `uint32` credential epoch and a nonzero `uint32` snapshot publication time;
- a Poseidon scoped nullifier derived from the signed holder secret and public scope hash at signals 11–12; and
- cryptographic binding of every one of the 18 public inputs by the generated Groth16 proof. Foundry mutates each
  input independently and requires the EVM verifier to reject it.

The exact proof then traverses the version registry, `ZkIdentityPredicateProver`, permanent host and replay storage
in Foundry. Under the repository's Solidity 0.8.28/Cancun profile, the generated 3,349-byte runtime costs 331,699 gas
for the raw verifier call and 419,219 gas for the full fresh dynamic-status consume. These are local research
observations, not target-chain or mainnet budgets.

## Trust split

| Boundary | Enforced here | Deliberately outside the circuit |
|---|---|---|
| Credential | issuer signature, signed issuer ID/status slot/epoch | passport ingestion, duplicate issuance, issuer key ceremony |
| Status | selected packed bit is clear under the public root | truth of the sanctions source, slot allocation, root publication authorization and availability |
| Policy | circuit ID fixes sanctions-clear semantics; result is true | Keccak policy hash and exact policy-root registration, checked by adapter + registry |
| Presentation | public subject/ranges and proof input binding | chain, host, consumer, subject, context, challenge and policy Keccak binding, recomputed by the adapter |
| Replay | holder-secret + public-scope Poseidon nullifier | scope Keccak derivation and replay storage, checked by SDK/adapter/host |
| Freshness | nonzero `uint32` publication signal | exact registered timestamp, future/stale checks and root retirement, checked by adapter + registry |

This split avoids embedding Keccak gadgets solely to repeat authenticated EVM checks, but it is safe only while the
adapter and registry remain mandatory parts of the verification path. The raw verifier alone does not authenticate
policy or presentation Keccak preimages.

## Known gaps and attacks still in scope

- The deterministic setup is fully compromised by design; anyone can forge proofs for this research verifier.
- Poseidon parameters, signature construction, nonce derivation, Baby-Jubjub subgroup handling and field encodings
  have not received an independent cryptographic audit.
- A malicious or compromised issuer can issue duplicate credentials, allocate the same status slot twice, publish
  dishonest roots or encode false passport attributes. Stage 2 governance and uniqueness rules must constrain it.
- Packed-status snapshots expose update metadata and require authenticated, available, fork-recoverable distribution.
- This circuit demonstrates sanctions-clear only. Age, country-set, document-validity and assurance relations need
  separate reviewed circuits or one explicitly selected policy VM; they must not reuse this circuit ID.
- Local Cancun gas does not establish Base, Celo, World Chain, Robinhood Chain or Ethereum operational cost.
- No mid-range mobile proof time or memory measurement exists for the 18-signal relation.

## Constraint-audit plan

1. Independently map every private credential field and every public signal to one relation, documenting fields
   that are intentionally adapter-authenticated.
2. Review Poseidon domains/parameters, bytes32 limb canonicality, Baby-Jubjub prime-order checks, scalar conversion,
   status-bit selection, Merkle direction derivation and nullifier preimage ordering.
3. Add adversarial witness tests for duplicate slots, zero/maximum values, field-modulus aliases, malformed curve
   points, stale roots and cross-circuit proof reuse.
4. Reproduce the Rust proof/VK, generated Solidity, runtime bytecode and all SDK/Solidity/Rust vectors in an
   independent environment; compare hashes rather than filenames.
5. Audit the registry/adapter/host composition, including retirement races, codehash pinning, replay domains and
   every failure/catch path. Raw-verifier success must never bypass this composition.

## Production ceremony and release plan

The production circuit source, compiler/toolchain, dependency lockfiles and public-input manifest must first be
frozen and independently audited. If circuit-specific Groth16 remains selected, run a documented multi-party Phase
2 ceremony over a reviewed Phase 1 transcript, verify every contribution, apply a public final beacon, publish the
complete transcript and independently reproduce the verifying key and Solidity bytecode. No deployer or issuer key
may participate as an implicit ceremony secret.

Only the independently reproduced verifier codehash may be proposed to the timelocked registry. Before activation,
run all target-testnet negative/replay/freshness tests, measure prover performance on representative mid-range
mobile hardware, measure raw and full transaction gas on every target chain, complete circuit/Solidity/browser and
privacy reviews, and close every Critical/High finding. L2 activation precedes Ethereum unless the recorded gate
supports simultaneous release.
