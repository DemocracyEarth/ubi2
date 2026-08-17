# V2 one-time issuance and packed-status slot registry

- **Status:** pre-deployment Stage 2 foundation; transitional Self bridge implemented, production cryptography not implemented
- **Contract:** [`ZkIdentityIssuanceRegistry.sol`](../../contracts/src/ZkIdentityIssuanceRegistry.sol)
- **Parent:** [`10-evm-zk-identity-v2.md`](10-evm-zk-identity-v2.md)

## Purpose

Give every accepted base credential exactly one `uint32` packed-status slot while preventing the same passport
issuance key or credential commitment from being registered twice. This registry is deliberately separate from
`ZkIdentityVersionRegistry`: issuance uniqueness is global to one canonical issuance registry, while presentation
circuit/root acceptance remains additive and circuit-specific.

This registry does **not** verify an e-passport, Self proof, issuer signature or credential attributes. The
transitional [`ZkIdentitySelfIssuanceBridge`](../../contracts/src/ZkIdentitySelfIssuanceBridge.sol) now authenticates
an exact off-chain Self verifier decision and binds its subject, holder commitment, scoped duplicate key, issuer
key, slot, epoch and immutable verifier configuration. A production circuit must eventually make those relations
cryptographically verifiable without trusting that service. See
[`v2-self-issuance-bridge.md`](v2-self-issuance-bridge.md).

## Public issuance domain

A bridge or issuance circuit must bind its proof-derived duplicate key to:

```text
keccak256(abi.encode(
  keccak256("org.proofofhumanity.zk-issuance"),
  uint16(1),
  chainId,
  issuanceRegistry
))
```

The Base Sepolia parity fixture for chain `84532` and registry
`0x1111111111111111111111111111111111111111` is
`0x3bf5571a5fb54037b033765a46a43d150ae8ffa32cb5c72c2ec11f6a572bd998` in both SDK and Solidity tests.
The domain prevents accidental cross-registry/cross-chain reuse; it does not select the circuit-native hash.

`duplicateKey` must be a nonzero, one-way proof output derived from the passport uniqueness material and this
domain. It must never be the passport number, raw Self nullifier or another portable global identifier. One
canonical production issuance registry issues the portable credential; consumers on other EVMs do not reissue it.

## State and transitions

1. Timelocked governance registers a nonzero `issuerKeyId`. Its first status slot is `1`; slot `0` remains the
   unallocated sentinel.
2. Governance authorizes one or more issuance authorities for that key. EOAs are pinned as code-free; a Safe or
   bridge contract is pinned to its authorization-time codehash. Authorizations and issuer-key registrations are
   additive, and retirement is irreversible.
3. The authority observes the next status id and current 90-day epoch, constructs the credential commitment, then
   calls `allocateCredential` with both expected values. A concurrent allocation or epoch rollover reverts without
   consuming the request.
4. The registry atomically consumes the duplicate key globally, consumes the canonical nonzero BN254 credential
   commitment globally, assigns the expected slot in the issuer-key namespace and emits the opaque commitment,
   slot and epoch. Slots are never chosen by the authority and never reused.
5. A separately authorized, codehash-pinned status publisher consumes the finalized allocation stream in exact
   slot order. Packed bits fail closed: `1` means unallocated or revoked and `0` means allocated and active. Each
   allocation therefore clears exactly one bit from the all-ones default; a revocation sets it back to `1`.
6. The publisher submits the nonzero canonical BN254 Poseidon root with the exact observed `nextStatusId`. A raced
   allocation rejects the publication. The registry assigns a monotonic snapshot id and records the root,
   `activatedThroughStatusId`, publication time and publisher without copying duplicate keys or credential fields.
7. Snapshots overlap until governance irreversibly revokes an exact snapshot. Issuer retirement makes every
   snapshot fail closed, while governance can still revoke old snapshots after retirement.

## Invariants and required failures

- The same `duplicateKey` fails across the original key, a rotated key and every authorized authority.
- The same credential commitment cannot represent two issuance records.
- Only an active authority under an active issuer key can allocate; contract codehash drift fails closed.
- Status ids increase monotonically within an issuer-key namespace; the final `uint32` slot allocates once, then
  exhaustion fails closed.
- A stale observed slot or epoch never consumes a duplicate key or commitment.
- Retired keys/authorities cannot be reactivated by re-registering the same identifier/address.
- The duplicate key is omitted from events. It is necessarily present in issuance calldata and queryable by a
  party that already knows it, so it must be registry-scoped and unlinkable to presentations.
- Credential commitments are opaque one-time issuance values and are absent from the 18 presentation signals.
- A status root is never valid merely because a publisher can submit it. The publisher must prove operationally
  that every finalized `CredentialAllocated` event through the declared watermark was processed once and in order,
  that no unallocated bit was cleared, and that every revocation was authorized. Reusing a root is rejected because
  every valid allocation or revocation changes at least one fail-closed bit.
- Target EVMs cannot synchronously read the canonical issuance chain. Their version-registry governance accepts a
  source snapshot only after independently reconciling its event range, finality and publisher authorization.

## Security boundary

The registry prevents replay of the **same correctly derived key**. A malicious or compromised authorized bridge
can still invent a different key for the same passport, submit a raw Self nullifier, bind false attributes, or
withhold a credential after allocation. The registry cannot distinguish those values by shape. Contract
authorization is therefore not proof of passport truth or privacy. Testnet integration must pin the Self
verifier/attestation version and extract the duplicate key and holder commitment from verified outputs rather than
accepting application-provided values.

The contract authenticates a root and its allocation watermark but cannot recompute an off-chain Poseidon tree.
A compromised status publisher can clear an unallocated/revoked bit or omit an activation. Production therefore
requires an independently reproducible public indexer, at least two-party root reconciliation before target-chain
acceptance, finalized source blocks, fork rollback/replay, signed snapshot artifacts, durable public distribution
and alerting. The issuance authority and status publisher must use separate production key paths.

An authority address's codehash does not pin an upgradeable proxy's implementation. Production governance must
authorize immutable bridge bytecode or separately constrain and timelock the proxy implementation; the codehash
check alone must not be described as an implementation pin.

Governance must keep this issuer-key registry aligned with the issuer keys accepted by
`ZkIdentityVersionRegistry`. The production owner is a timelocked multisig; a deployer EOA must not remain owner.
No production deployment is authorized by this pre-deployment implementation.

## Verification in this slice

- Foundry covers global duplicate rejection, commitment replay, authority/key/publisher retirement, codehash drift,
  allocation/publication race rollback, canonical roots, overlapping/exact snapshot revocation, post-retirement
  incident response, event privacy and both `uint32`/epoch exhaustion boundaries.
- TypeScript and Solidity pin the issuance-domain vector and reject zero chain/registry trust domains.
- The SDK exposes strict canonical-root validation and exact publication calldata; the research circuit fixture now
  starts every unallocated packed bit at `1` and clears only its allocated slot.
- The deterministic reference builder consumes strict finalized block transcripts, enforces chain/parent/log
  continuity and dense allocation order, rolls failed blocks back atomically, rewinds known forks, emits sorted
  sparse snapshots, restores durable checkpoints only after recomputing their exact root, and produces witnesses
  accepted by the depth-24 research circuit.
- The SDK finalized reader requires the RPC `finalized` tag, bounded 512-block batches and byte-exact branch/log
  continuity. Canonical snapshot JSON has a pinned Keccak content hash; chain/registry-bound EIP-712 attestations
  require at least two distinct application-configured reconcilers to agree on identical content before deriving
  publisher calldata. Split roots, duplicate/unknown signers and malformed checkpoints fail closed. The reference
  reconciler currently supports 65-byte ECDSA signatures from EOAs; ERC-1271 validation remains production work.
- The deployable status-operator package runs that flow as a single-writer daemon with fsync-and-rename checkpoints,
  immutable signed artifacts, encrypted Foundry-keystore signing, loopback-only read endpoints and a separate fleet
  gate. The fleet gate uses a third finalized RPC and blocks publication on unavailability, staleness, withholding,
  wrong signers, split content, or an unavailable/mismatched content-addressed artifact. It can atomically archive a
  secretless bundle whose checksum, signatures, immutable artifacts and fleet decision reproduce offline.
  Verification pins the bundle's public trust metadata to a separately reviewed fleet config; a strict manifest
  checks the intrinsic restart, withholding, divergence and recovery evidence relationships without treating
  embedded timestamps, host actions or paging acknowledgements as self-attested proof. Systemd hardening and drill
  templates are included. A transaction-free readiness gate now binds two operator configs and the third-RPC fleet
  config to a strict public trust record, checks finalized registry bytecode/deployment/ownership/issuer/publisher
  state across all three RPC paths, and archives a secretless non-overwriting report. Physical independence,
  on-host hashes, keystore inspection and authoritative timestamps remain external; no canonical testnet host or
  completed drill is claimed yet.
- The local Cancun allocation and first snapshot-publication writes are pinned at 129,886 and 103,407 gas. They
  exclude passport-proof verification and Poseidon tree construction and are not target-chain budgets.

## Next implementation slice

Run the packaged reconciler instances and fleet gate on three independent canonical-testnet trust paths, connect
real paging to non-ready fleet reports, and capture restart/withholding/divergence drills. The holder-side
commitment candidate and sanitized receipt transcript are now pinned as reference tooling in
[`v2-holder-credential-commitment.md`](v2-holder-credential-commitment.md). Next capture one live canonical-testnet
issuance, duplicate rejection, activation, revocation, stale-root overlap and target-chain acceptance transcript.
Do not claim grant-preserving slot/epoch race refresh for the new commitment until its recorded integration
decision is resolved.
