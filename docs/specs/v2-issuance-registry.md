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
5. The event stream is input to the future packed-status publisher. Revocation, root publication, bridge proof
   verification and credential rotation are later transitions and are not implied by allocation.

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

## Security boundary

The registry prevents replay of the **same correctly derived key**. A malicious or compromised authorized bridge
can still invent a different key for the same passport, submit a raw Self nullifier, bind false attributes, or
withhold a credential after allocation. The registry cannot distinguish those values by shape. Contract
authorization is therefore not proof of passport truth or privacy. Testnet integration must pin the Self
verifier/attestation version and extract the duplicate key and holder commitment from verified outputs rather than
accepting application-provided values.

An authority address's codehash does not pin an upgradeable proxy's implementation. Production governance must
authorize immutable bridge bytecode or separately constrain and timelock the proxy implementation; the codehash
check alone must not be described as an implementation pin.

Governance must keep this issuer-key registry aligned with the issuer keys accepted by
`ZkIdentityVersionRegistry`. The production owner is a timelocked multisig; a deployer EOA must not remain owner.
No production deployment is authorized by this pre-deployment implementation.

## Verification in this slice

- Foundry covers global duplicate rejection, commitment replay, authority/key retirement, codehash drift, race
  rollback, invalid/canonical fields, event privacy and both `uint32`/epoch exhaustion boundaries.
- TypeScript and Solidity pin the issuance-domain vector and reject zero chain/registry trust domains.
- The local Cancun allocation write is pinned at 129,763 gas. It excludes passport-proof verification and is not a
  target-chain budget.

## Next implementation slice

Run the bridge and its grant-preserving authorization refresh on one canonical testnet with an isolated
authority, connect the holder-side circuit-native credential commitment, and capture one live issuance,
slot-race refresh and duplicate rejection. Then implement the packed-status activation/publication transition
without storing private credential material.
