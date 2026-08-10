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

The complete secretless CI gate additionally enforces target-contract coverage, the four-call gas
baseline, Solidity/TypeScript EIP-712 parity, and a local rehearsal of the Phase 2 deployment tooling.
See [PHASE2.md](PHASE2.md) for testnet deployment instructions.
