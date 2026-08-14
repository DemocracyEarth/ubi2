# ubi2 `contracts/` — Proof of Humanity (EVM)

Foundry package for the **Proof of Humanity** soulbound NFT — the on-chain, cross-chain half of
proofofhumanity.org. A human verified via a Self (self.xyz) ZK passport proof mints an **ERC-5192
soulbound** token carrying only a deterministic nullifier and coarse verification epoch — no nationality,
age, gender, sanctions result, or identity. One-human-one-token **per chain** via Self's nullifier.

## Contracts

- `src/ProofOfHumanity.sol` — the soulbound SBT.
  - **MVP mint** `mintWithVoucher(HumanityVoucher, signature)`: proofofhumanity.org's backend verifies the
    Self proof off-chain and signs an EIP-712 `HumanityVoucher`; the human (or a relayer) redeems it. Works
    on **any EVM chain** — deploy the identical bytecode everywhere. Uniqueness and monotonic refresh are
    keyed on the nullifier; the issuer is rotatable by the owner (`setIssuer`, `Ownable`).
  - **Trustless upgrade seam** `IHumanityProofVerifier` — the future `mintWithProof(...)` verifies the
    Groth16 proof on-chain against a mirrored Self registry root (declared, intentionally unimplemented).
- `src/PredicateVerifier.sol` — permanent v1 issuer-attestation host plus the proof-system-neutral
  `IPredicateProver` seam. Before calling a prover it wraps the application context with the actual consuming
  contract. Stateful proof consumption additionally requires `IPredicateProverReplay`; v2 spends the authenticated
  scoped nullifier, not the presenting wallet, so wallet changes do not reset a one-per-scope gate.
- `src/ZkIdentityPredicateProver.sol` — **pre-deployment** v2 adapter for the pinned 18-signal layout. It binds
  chain, host, consumer, subject, policy, action context, challenge and nullifier mode, then resolves a governed
  verifier/issuer/root and calls an exact eight-word/18-input raw verifier. Do not configure it until a reviewed
  production circuit and ceremony artifact exist.
- `src/ZkIdentityVersionRegistry.sol` — **pre-deployment** additive circuit/codehash, issuer and root governance
  prototype. Production ownership requires a timelock-controlled multisig.

## V2 adapter developer preview

Clients encode only the application tuple; `PredicateVerifier` adds the actual consumer envelope internally:

```ts
import { encodeZkPredicateProofContext } from "@ubi2/sdk";

const context = encodeZkPredicateProofContext({
  context: actionContext,       // bytes32 stable action/scope
  challenge,                   // fresh non-zero bytes32
  nullifierMode: "single-use",
});
```

The consumer calls `consumeWithProof(proof, publicSignals, context, policyHash, presenter)`. For read-only checks,
call `checkProof` from the intended consumer or use `checkProofFor(..., consumer)` explicitly. `policyHash` is the
v2 canonical policy hash, not a raw private attribute. The proof is ABI-encoded `uint256[8]`; public signals are
the exact 18 entries documented in [`docs/specs/10-evm-zk-identity-v2.md`](../docs/specs/10-evm-zk-identity-v2.md).

For a sanctions policy, use SDK `dynamicStatusPolicyRegistration` to derive the exact governance inputs. Proposed
ADR-0011 defines signal 17 as the snapshot publication Unix time; the registry recomputes the policy hash and the
adapter rejects unknown, retired, future, mismatched or stale snapshots. This remains a pre-deployment seam: the
production circuit must prove the dynamic-policy/status relation, and stub-verifier gas is not a production
proof-cost estimate.

```ts
import { dynamicStatusPolicyRegistration } from "@ubi2/sdk";

const registration = dynamicStatusPolicyRegistration({
  policy: {
    kind: "dynamic-status",
    status: "sanctions-clear",
    providerId: "self:ofac",
    listVersion: "2026-08-14",
    statusRoot,
    maximumAgeSeconds: 86_400,
  },
  publishedAt, // uint32 Unix seconds assigned to this exact public snapshot
});

// registerDynamicStatusPolicy(...)
const args = [
  registration.providerIdHash,
  registration.listVersionHash,
  registration.statusRoot,
  registration.publishedAt,
  registration.maximumAgeSeconds,
] as const;
```

The transaction return/event policy hash must equal `registration.policyHash`. Applications request that exact
hash; they must not request an ambiguous “latest sanctions status.”

## Setup (dependencies are not vendored)
`lib/` is git-ignored; restore the pinned deps with:
```shell
forge install \
  OpenZeppelin/openzeppelin-contracts@cab19933c33c2ad1d4c7a84864a3601dddfd16f3 \
  foundry-rs/forge-std@bf647bd6046f2f7da30d0c2bf435e5c76a780c1b \
  --no-git
```

Those commits correspond to OpenZeppelin `v5.7.0` and forge-std `v1.16.2`. CI uses Foundry
`v1.5.1`, the version that produced the committed deterministic gas baseline.

## Build / test / format
```shell
forge build
forge test -vv
forge fmt
```

The complete secretless CI gate additionally enforces target-contract coverage, deterministic gas
baseline, Solidity/TypeScript EIP-712 parity, and a local rehearsal of the Phase 2 deployment tooling.
See [PHASE2.md](PHASE2.md) for testnet deployment instructions.
