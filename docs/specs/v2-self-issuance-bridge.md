# V2 Self issuance bridge

- **Status:** pre-deployment testnet bridge; transitional off-chain Self trust root
- **Contracts:** [`ZkIdentitySelfIssuanceBridge.sol`](../../contracts/src/ZkIdentitySelfIssuanceBridge.sol),
  [`ZkIdentityIssuanceRegistry.sol`](../../contracts/src/ZkIdentityIssuanceRegistry.sol)
- **SDK:** [`zk-self-issuance.ts`](../../packages/sdk/src/zk-self-issuance.ts)
- **Parent:** [`10-evm-zk-identity-v2.md`](10-evm-zk-identity-v2.md)

## What this slice establishes

The exact supported Self e-passport proof is verified by the pinned
`@selfxyz/core@1.0.8` backend before a private credential can receive a one-time status slot. The
holder supplies a canonical BN254 credential commitment before scanning; Self binds it, the wallet
subject, disclosure policy, and a random browser capability into the proof. The server then:

1. accepts only the configured Self scope, callback endpoint, staging/production environment and
   e-passport attestation id;
2. derives an opaque duplicate key from the raw Self nullifier and the registry's chain/address
   issuance domain;
3. reads the registry issuer slot, epoch, bridge authorization/codehash and all immutable bridge
   trust inputs at one block;
4. signs a ten-minute EIP-712 authorization binding the subject, duplicate key, credential
   commitment, issuer key, expected slot, expected epoch and exact Self verifier configuration; and
5. returns only the serialized authorization and signature. The raw Self nullifier is neither
   stored nor returned in the v2 path.

The verified subject submits `issue(authorization, signature)` itself. The bridge rejects another
caller, an expired authorization, a changed signed field, a different chain/bridge, signer,
issuer key or Self configuration. The registry then atomically rejects duplicate passports,
commitments, stale slots and stale epochs.

## Exact domains

The bridge EIP-712 domain is:

```text
name              = "ProofOfHumanitySelfIssuance"
version           = "1"
chainId           = canonical issuance chain
verifyingContract = immutable bridge
```

Its signed primary type is:

```text
SelfIssuanceAuthorization(
  address subject,
  bytes32 duplicateKey,
  uint256 credentialCommitment,
  bytes32 issuerKeyId,
  uint32 expectedStatusId,
  uint32 expectedEpoch,
  uint64 deadline,
  bytes32 selfConfigId
)
```

`selfConfigId` commits to the exact scope, public callback endpoint, environment, attestation id
and Self verifier package/protocol tag. Those strings are byte-exact: changing the production
origin or verifier version requires a new bridge deployment and additive governance rotation.

The verifier service derives, in memory:

```text
duplicateKey = keccak256(abi.encode(
  keccak256("org.proofofhumanity.zk-issuance:self-nullifier"),
  uint16(1),
  registry.issuanceDomain(),
  uint256(rawSelfNullifier)
))
```

The derivative necessarily appears in issuance calldata but is scoped to one registry. The raw
portable Self nullifier must not appear in calldata, events, storage, API responses or logs.

## Developer integration

An application with an isolated holder prover calls `buildSelfIssuanceApp(...)`, not the legacy
`buildSelfApp(...)`. The commitment must already authenticate the holder secret and private base
credential fields; the browser helper deliberately refuses to invent a placeholder commitment.
After Self verification, poll `/api/self-verify` with the same address and session capability. A
ready v2 response contains `zkIssuance`, which can be submitted with:

```ts
import { deserializeZkSelfIssuanceAuthorization, encodeZkSelfIssuance } from "@ubi2/sdk";

const data = encodeZkSelfIssuance({
  authorization: response.zkIssuance.authorization,
  signature: response.zkIssuance.signature,
});

await walletClient.sendTransaction({
  account,
  chain,
  to: response.zkIssuance.bridge,
  data,
});
```

The connected account must equal the proof-bound `subject`. An `UnexpectedStatusId` or
`UnexpectedIssuanceEpoch` means the short-lived authorization lost a race and must be refreshed by
the verified issuance service; it is not permission to change the signed values locally.

The server path is disabled unless all six `ZK_SELF_ISSUANCE_*` variables documented in
[`apps/proofofhumanity/DEPLOY.md`](../../apps/proofofhumanity/DEPLOY.md) are present. Partial or
on-chain-mismatched configuration fails closed.

## Deployment and rotation

For a testnet rehearsal, compute `ZK_SELF_CONFIG_ID` with `zkSelfVerifierConfigId`, record only the
verification authority's public address in the deployment environment, and run:

```shell
forge script script/DeployZkSelfIssuance.s.sol:DeployZkSelfIssuance \
  --rpc-url "$RPC_URL" --account poh-testnet-deployer --broadcast --verify
```

The script deploys a new registry, registers the issuer namespace, deploys the immutable bridge,
authorizes its codehash, and initiates two-step ownership transfer when a different owner is set.
The final owner must separately call `acceptOwnership`. Testnet source verification, bytecode,
configuration and one live duplicate-rejection transcript must be recorded before mainnet review.

Signer/configuration rotation never mutates a live bridge. Governance authorizes a new immutable
bridge for the same issuer key, verifies it, retires the old bridge in the registry, and updates the
server only after the new authorization is active.

## Honest limitations and remaining release gates

This is not trustless passport verification: a compromised verification authority can still invent
duplicate keys or authorize false commitments. The contract makes exactly what that authority
attested tamper-evident and replay-safe; it cannot inspect the Self proof. Production therefore
still requires either an audited on-chain verifier for the exact Self proof/version or a native
passport-to-commitment circuit, plus an HSM/threshold service, durable private handoff, monitoring,
rate limits and incident/rotation drills.

The current UI does not generate the production circuit-native credential commitment. Only
developer/prover integrations can enter this v2 path until the Stage 3 holder vault and local
prover are connected. No random or EVM-keccak placeholder is promoted as a real credential.

## Verification evidence

- Foundry covers valid issuance, subject binding, expiry, signer/field/domain tampering, immutable
  trust inputs, duplicate rejection, slot-race rollback and event privacy.
- SDK tests pin the verifier configuration id, scoped duplicate key, EIP-712 digest, signer
  recovery, JSON serialization and exact calldata selector.
- The product test pins the proof-bound request grammar and rejects zero/non-canonical commitments.
- The local Cancun bridge-plus-registry write is pinned at **140,014 gas**. Self verification is
  off-chain and excluded; this is not target-chain evidence.
