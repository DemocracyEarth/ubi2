/** Minimal ABI shared by the predicate center and the server-side deployment binding checks. */
export const predicateVerifierAbi = [
  {
    type: "function",
    name: "owner",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
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
    name: "prover",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "check",
    stateMutability: "view",
    inputs: [
      {
        name: "att",
        type: "tuple",
        components: [
          { name: "consumer", type: "address" },
          { name: "context", type: "bytes32" },
          { name: "predicate", type: "bytes32" },
          { name: "result", type: "bool" },
          { name: "subject", type: "address" },
          { name: "epoch", type: "uint32" },
          { name: "nonce", type: "uint256" },
        ],
      },
      { name: "signature", type: "bytes" },
      { name: "presenter", type: "address" },
      { name: "consumer", type: "address" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "consume",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "att",
        type: "tuple",
        components: [
          { name: "consumer", type: "address" },
          { name: "context", type: "bytes32" },
          { name: "predicate", type: "bytes32" },
          { name: "result", type: "bool" },
          { name: "subject", type: "address" },
          { name: "epoch", type: "uint32" },
          { name: "nonce", type: "uint256" },
        ],
      },
      { name: "signature", type: "bytes" },
      { name: "presenter", type: "address" },
    ],
    outputs: [],
  },
] as const;
