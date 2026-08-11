# Proof of Humanity deployments

This registry records public release artifacts for the production contract stack:
`PoHCardRenderer`, `ProofOfHumanity`, and `PredicateVerifier`. It never lists the demo-only
`SybilResistantVote` contract. Contract and transaction links are public; no wallet credential or
RPC service secret belongs in this file.

## Phase 2 testnets

All completed rows use deployer/owner `0x26250e47500943464290A77ae3508a3001d9B69d` and issuer
`0x1D6cB99ff20223d730Ae5D4680EC5154B7FdAefe`. These are disposable testnet roles, not the production
owner multisig or production issuer.

| Network | Deploy commit | PoHCardRenderer | ProofOfHumanity | PredicateVerifier | Live gate |
| --- | --- | --- | --- | --- | --- |
| Base Sepolia (`84532`) | [`6159829`](https://github.com/DemocracyEarth/ubi2/commit/6159829) | [`0x6e87…5acf`](https://sepolia.basescan.org/address/0x6e8709c7816de1d994738b6b2d7548c754ce5acf#code) | [`0x06bd…8029`](https://sepolia.basescan.org/address/0x06bd253009f74ad934a4daeac133b153d9fe8029#code) | [`0x2051…a9d6`](https://sepolia.basescan.org/address/0x2051d33c2f10cdd3739324afc4c6fd957564a9d6#code) | verified source; mint/replay/soulbound/predicate PASS |
| Ethereum Sepolia (`11155111`) | [`751e8fc`](https://github.com/DemocracyEarth/ubi2/commit/751e8fce183c70343ef2d59b122ea5329509767b) | [`0x82B5…E680`](https://sepolia.etherscan.io/address/0x82b5efbb809645baa6770bd102ce7649e466e680#code) | [`0x9538…f347`](https://sepolia.etherscan.io/address/0x9538c846ac749444729eae41599ab7a26683f347#code) | [`0x3AAC…796B`](https://sepolia.etherscan.io/address/0x3aac42302ab365b8d0af2ee0a2f44adef3e2796b#code) | verified source; mint/replay/soulbound/predicate PASS |
| Celo Sepolia (`11142220`) | pending | — | — | — | pending |
| Robinhood Chain Testnet (`46630`) | [`032ade9`](https://github.com/DemocracyEarth/ubi2/commit/032ade93f16aa63ab0bec3f686d5900f45fa407c) | [`0x7691…CE53`](https://explorer.testnet.chain.robinhood.com/address/0x7691e41cdd222ad5552a09ed3840433a16c5ce53?tab=contract) | [`0xb031…0E12`](https://explorer.testnet.chain.robinhood.com/address/0xb0317d3481a2a78959b51c4d5dce3f4991e50e12?tab=contract) | [`0x4A1a…307e`](https://explorer.testnet.chain.robinhood.com/address/0x4a1a892552b284eeda540ecf3e3e44797a9d307e?tab=contract) | verified source; mint/replay/soulbound/predicate PASS |
| World Chain Sepolia (`4801`) | pending | — | — | — | pending |

## Transactions

### Base Sepolia

- Renderer deployment: [`0xe15d…78be`](https://sepolia.basescan.org/tx/0xe15d67565e17ddc7233c178b850e5cf4e4593accffc2736cc92df794851c78be)
- ProofOfHumanity deployment: [`0x32e0…8d6`](https://sepolia.basescan.org/tx/0x32e065de63c23ee570053ceb24592d611dab91dd10ca2bd2b77dd8f5bd1b48d6)
- PredicateVerifier deployment: [`0x3ddc…2ed3`](https://sepolia.basescan.org/tx/0x3ddc17ca235bab8d8efc89bb8fd6739f7afe74d7c79f0a507a439a0b34932ed3)
- Live mint: [`0x03e5…9126`](https://sepolia.basescan.org/tx/0x03e51317f2a0fa3305c952595b3111a9af8f50b044405771ab5936a74ba19126)

### Ethereum Sepolia

- Renderer deployment: [`0x6da6…0a46`](https://sepolia.etherscan.io/tx/0x6da6f6919b10bb13a759b80ba7ae0609f3fb0a9c30d29eaa61c420395bc40a46)
- ProofOfHumanity deployment: [`0x5d19…1b70`](https://sepolia.etherscan.io/tx/0x5d19784851034711874983c8b260869463c5634492a1d68526f0c49b97b81b70)
- PredicateVerifier deployment: [`0x3f56…99d1`](https://sepolia.etherscan.io/tx/0x3f56db2c2c75202580f896deefd6a26ff5639ff3727803ba7daa85f4dfb399d1)
- Live mint: [`0x0939…521b`](https://sepolia.etherscan.io/tx/0x0939306180a58cb6fad4fe13410bd540f69a28a84df721eb203ce7aae1c2521b)

### Robinhood Chain Testnet

- Renderer deployment: [`0xa100…701a`](https://explorer.testnet.chain.robinhood.com/tx/0xa1000fce0ae912fc7a621159fe410f92c6d88d5c12f28d42dbbe7de739a0701a)
- ProofOfHumanity deployment: [`0x656a…59b2`](https://explorer.testnet.chain.robinhood.com/tx/0x656a07784ea949dd112390bd61f7961aec24b76297fd7d21ff00c831843f59b2)
- PredicateVerifier deployment: [`0x5f60…53ae`](https://explorer.testnet.chain.robinhood.com/tx/0x5f60519efcb90e728113c94f0135c027ac7758c707193385f25be6f04bfc53ae)
- Live mint: [`0xcaa3…32ab`](https://explorer.testnet.chain.robinhood.com/tx/0xcaa37a4963e011e6f2e1d7d2bf30cbcd71980429492a1fcdb8a93f3702bb32ab)

The live gate checks deployed bytecode, owner/issuer/renderer wiring, an unset predicate prover,
credential validity, ERC-5192 locking, voucher replay rejection, transfer rejection, a signed
`age>=18` predicate, and wrong-subject rejection. Predicate checks are read-only and therefore have
no transaction hash.
