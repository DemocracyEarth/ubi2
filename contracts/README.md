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
forge install OpenZeppelin/openzeppelin-contracts@v5.7.0 foundry-rs/forge-std --no-git
```

## Build / test / format
```shell
forge build
forge test -vv
forge fmt
```
