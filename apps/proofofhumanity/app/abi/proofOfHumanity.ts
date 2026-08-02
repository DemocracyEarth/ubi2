/**
 * Minimal ProofOfHumanity ABI — only the entrypoints this app touches.
 *
 * Hand-mirrored from `contracts/src/ProofOfHumanity.sol`. The `HumanityVoucher` tuple field order
 * here MUST match the Solidity struct AND `app/lib/voucher.ts::VOUCHER_TYPES`:
 *   (address to, uint256 nullifier, uint8 ageFlags, bytes3 nationality, uint8 gender,
 *    bool ofacClear, uint64 expiry)
 * and the `Attributes` tuple returned by `attributesOf`:
 *   (uint8 ageFlags, bytes3 nationality, uint8 gender, bool ofacClear, uint64 expiry)
 */
export const proofOfHumanityAbi = [
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
          { name: "ageFlags", type: "uint8" },
          { name: "nationality", type: "bytes3" },
          { name: "gender", type: "uint8" },
          { name: "ofacClear", type: "bool" },
          { name: "expiry", type: "uint64" },
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
    name: "attributesOf",
    stateMutability: "view",
    inputs: [{ name: "tokenId", type: "uint256" }],
    outputs: [
      {
        name: "",
        type: "tuple",
        components: [
          { name: "ageFlags", type: "uint8" },
          { name: "nationality", type: "bytes3" },
          { name: "gender", type: "uint8" },
          { name: "ofacClear", type: "bool" },
          { name: "expiry", type: "uint64" },
        ],
      },
    ],
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
          { name: "ageFlags", type: "uint8" },
          { name: "nationality", type: "bytes3" },
          { name: "gender", type: "uint8" },
          { name: "ofacClear", type: "bool" },
          { name: "expiry", type: "uint64" },
        ],
      },
    ],
    outputs: [{ name: "", type: "bytes32" }],
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

/** Decoded `Attributes` struct shape returned by `attributesOf`. */
export interface OnChainAttributes {
  ageFlags: number;
  nationality: `0x${string}`;
  gender: number;
  ofacClear: boolean;
  expiry: bigint;
}
