/**
 * Minimal ProofOfHumanity ABI — only the entrypoints this app touches.
 *
 * Hand-mirrored from `contracts/src/ProofOfHumanity.sol`. The `HumanityVoucher` tuple field order
 * here MUST match the Solidity struct AND `app/lib/voucher.ts::VOUCHER_TYPES`:
 *   (address to, uint256 nullifier, uint32 epoch)
 * The credential is minimal: per token the contract stores only `nullifier` + `epoch`. There are
 * NO attribute getters — nationality / gender / age never touch the chain.
 */
export const proofOfHumanityAbi = [
  {
    type: "event",
    name: "HumanityMinted",
    inputs: [
      { name: "tokenId", type: "uint256", indexed: true },
      { name: "nullifier", type: "uint256", indexed: true },
      { name: "to", type: "address", indexed: true },
    ],
  },
  {
    type: "event",
    name: "HumanityRefreshed",
    inputs: [
      { name: "tokenId", type: "uint256", indexed: true },
      { name: "nullifier", type: "uint256", indexed: true },
      { name: "epoch", type: "uint32", indexed: false },
    ],
  },
  {
    type: "function",
    name: "mintWithVoucher",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "voucher",
        type: "tuple",
        components: [
          { name: "to", type: "address" },
          { name: "nullifier", type: "uint256" },
          { name: "epoch", type: "uint32" },
        ],
      },
      { name: "signature", type: "bytes" },
    ],
    outputs: [{ name: "tokenId", type: "uint256" }],
  },
  {
    type: "function",
    name: "tokenURI",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "string" }],
  },
  {
    type: "function",
    name: "hashVoucher",
    stateMutability: "view",
    inputs: [
      {
        name: "voucher",
        type: "tuple",
        components: [
          { name: "to", type: "address" },
          { name: "nullifier", type: "uint256" },
          { name: "epoch", type: "uint32" },
        ],
      },
    ],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "currentEpoch",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "uint32" }],
  },
  {
    type: "function",
    name: "isValid",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "domainSeparator",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "balanceOf",
    stateMutability: "view",
    inputs: [{ name: "owner", type: "address" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "tokenOfNullifier",
    stateMutability: "view",
    inputs: [{ name: "nullifier", type: "uint256" }],
    outputs: [{ name: "", type: "uint256" }],
  },
  {
    type: "function",
    name: "issuer",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "owner",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "ownerOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "locked",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;
